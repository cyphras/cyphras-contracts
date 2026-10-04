import {
  Account,
  Address,
  FeeBumpTransaction,
  Operation,
  type Transaction,
  TransactionBuilder,
  xdr,
} from "@stellar/stellar-base";
import { bytesToHex } from "../bytes.ts";
import { CyphrasError, type ErrorDetails, fail } from "../errors.ts";
import { type MetaEvent, type SorobanRpc, type TransactionStatus, keyId } from "../net/rpc.ts";
import { vaultErrorName } from "./errors.ts";
import { accountKey } from "./state.ts";

/** The network fee of a Stellar transaction the SDK built, in stroops. */
export interface NetworkFee {
  // What the transaction bids for inclusion, and what its simulated resources cost.
  readonly inclusion: bigint;
  readonly resource: bigint;
  readonly total: bigint;
}

/** The most the SDK lets a transaction it builds pay, in stroops. */
export interface NetworkFeeCaps {
  readonly inclusion: bigint;
  readonly resource: bigint;
}

export const DEFAULT_NETWORK_FEE_CAPS: NetworkFeeCaps = {
  inclusion: 100_000n,
  resource: 10_000_000n,
};

/**
 * A Stellar wallet that signs transactions, in the shape wallets already expose. The result is
 * the signed transaction envelope as base64 XDR, or an object carrying it as `signedTxXdr`. A
 * signer that can ask its user implements confirmFee: every transaction the SDK builds shows it the
 * network fee before signing, and goes ahead only on true.
 */
export interface TransactionSigner {
  readonly publicKey: string;
  signTransaction(xdr: string, networkPassphrase: string): Promise<unknown>;
  confirmFee?(fee: NetworkFee): boolean | Promise<boolean>;
}

/**
 * What a call on the vault's exit queue may need beyond its simulation, when the ledger it lands in
 * leads it down another path than the state it was simulated against did: the entries that path
 * writes, in the order they are added, and the instructions, written bytes, bytes of new
 * persistent entries, kept for `rentLedgers` or the network's least for a new entry if that is
 * longer, and event bytes it may add.
 */
export interface Extra {
  readonly readWrite: readonly xdr.LedgerKey[];
  readonly instructions: number;
  readonly writeBytes: number;
  readonly newBytes: number;
  readonly rentLedgers: number;
  readonly eventBytes: number;
}

// A call the signer authorizes as the transaction source: the vault function, and the token
// transfers it may make from the signer's account. A call on the exit queue, whose path the vault
// decides in the ledger it lands in, names what it may need beyond its simulation, from the
// footprint the simulation found; another transaction in the same ledger can still move the queue
// past it, and such a call that fails on the host's storage goes again after a fresh simulation.
export interface VaultCall {
  readonly fn: string;
  readonly args: readonly xdr.ScVal[];
  readonly transfers: readonly { readonly token: string; readonly args: readonly xdr.ScVal[] }[];
  readonly extend?: (footprint: xdr.LedgerFootprint) => Promise<Extra>;
}

export interface InvokeContext {
  readonly rpc: SorobanRpc;
  // A second provider, which must report a failure on the host's storage too before a call goes
  // again.
  readonly second: SorobanRpc | undefined;
  readonly networkPassphrase: string;
  readonly vault: string;
  readonly feeCaps: NetworkFeeCaps;
  // Milliseconds since the epoch.
  readonly now: () => number;
  readonly sleep: (ms: number) => Promise<void>;
}

export interface InvokeResult {
  readonly hash: string;
  readonly ledger: number;
  readonly returnValue: xdr.ScVal | undefined;
  readonly events: readonly MetaEvent[];
}

const TIMEOUT_SECONDS = 300;
const MIN_INCLUSION_FEE = 100n;
const POLL_MS = 1_500;
// How often a call on the exit queue goes in all while it fails on the host's storage.
const ATTEMPTS = 5;
// A provider asked about a transaction it does not hold yet is asked again, at most this many
// times and for this long in all, with each request cut off after ASK_REQUEST_MS: one that hangs
// must not keep the signer's account waiting.
const ASK_POLLS = 20;
const ASK_MS = 30_000;
const ASK_REQUEST_MS = 5_000;
// The bytes added to what a call may read for each account or trustline in its footprint, and to
// what it may write for each it writes: anyone can grow their own account, by signers or
// sponsorships, between a simulation and the ledger the call lands in. An account entry holds at
// most about 2 KB.
const CLASSIC_PAD = 2048;
// The size of the TTL entry the network writes with a persistent entry's rent.
const TTL_ENTRY_BYTES = 48;

// The network's Soroban fees and limits. Fees are in stroops: per 10,000 instructions, per entry
// and per 1 KiB.
interface LedgerCosts {
  readonly instruction: bigint;
  readonly readEntry: bigint;
  readonly writeEntry: bigint;
  readonly read1KB: bigint;
  readonly write1KB: bigint;
  readonly historical1KB: bigint;
  readonly txSize1KB: bigint;
  readonly events1KB: bigint;
  readonly rent1KB: bigint;
  readonly rentDenominator: bigint;
  readonly minPersistentTTL: number;
  readonly maxInstructions: number;
  readonly maxReadEntries: number;
  readonly maxWriteEntries: number;
  readonly maxFootprint: number;
  readonly maxReadBytes: number;
  readonly maxWrites: number;
}

const ceilDiv = (a: bigint, b: bigint): bigint => (a + b - 1n) / b;

// The fee of a number of bytes at a rate per 1,024 of them, rounded up as the network rounds it.
const perKB = (bytes: number, rate: bigint): bigint => ceilDiv(BigInt(bytes) * rate, 1024n);

// The network's rent for 1 KiB of persistent state over a rent period, which grows with the size
// of the Soroban state as the host computes it.
function rentPerKB(
  size: bigint,
  low: bigint,
  high: bigint,
  target: bigint,
  growth: bigint,
): bigint {
  const t = target > 1n ? target : 1n;
  const fee =
    size < t
      ? ceilDiv((high - low) * size, t) + low
      : high + ceilDiv((high - low) * (size - t) * growth, t);
  return fee > 1000n ? fee : 1000n;
}

async function ledgerCosts(rpc: SorobanRpc): Promise<LedgerCosts> {
  const id = xdr.ConfigSettingId;
  const keys = [
    id.configSettingContractComputeV0(),
    id.configSettingContractLedgerCostV0(),
    id.configSettingContractLedgerCostExtV0(),
    id.configSettingContractHistoricalDataV0(),
    id.configSettingContractEventsV0(),
    id.configSettingContractBandwidthV0(),
    id.configSettingStateArchival(),
    id.configSettingLiveSorobanStateSizeWindow(),
  ].map((configSettingId) =>
    xdr.LedgerKey.configSetting(new xdr.LedgerKeyConfigSetting({ configSettingId })),
  );
  const { entries } = await rpc.getLedgerEntries(keys);
  const setting = (key: xdr.LedgerKey | undefined): xdr.ConfigSettingEntry => {
    const entry = key === undefined ? undefined : entries.get(keyId(key));
    if (entry === undefined) fail("rpc_error", "the network's fee settings are missing");
    return entry.data.configSetting();
  };
  const compute = setting(keys[0]).contractCompute();
  const cost = setting(keys[1]).contractLedgerCost();
  const ext = setting(keys[2]).contractLedgerCostExt();
  const archival = setting(keys[6]).stateArchivalSettings();
  const window = setting(keys[7]).liveSorobanStateSizeWindow();
  if (window.length === 0) fail("rpc_error", "the network's fee settings are missing");
  const int = (v: { toString(): string }): bigint => BigInt(v.toString());
  const size = window.reduce((sum, n) => sum + int(n), 0n) / BigInt(window.length);
  return {
    instruction: int(compute.feeRatePerInstructionsIncrement()),
    readEntry: int(cost.feeDiskReadLedgerEntry()),
    writeEntry: int(cost.feeWriteLedgerEntry()),
    read1KB: int(cost.feeDiskRead1Kb()),
    write1KB: int(ext.feeWrite1Kb()),
    historical1KB: int(setting(keys[3]).contractHistoricalData().feeHistorical1Kb()),
    txSize1KB: int(setting(keys[5]).contractBandwidth().feeTxSize1Kb()),
    events1KB: int(setting(keys[4]).contractEvents().feeContractEvents1Kb()),
    rent1KB: rentPerKB(
      size,
      int(cost.rentFee1KbSorobanStateSizeLow()),
      int(cost.rentFee1KbSorobanStateSizeHigh()),
      int(cost.sorobanStateTargetSizeBytes()),
      BigInt(cost.sorobanStateRentFeeGrowthFactor()),
    ),
    rentDenominator: int(archival.persistentRentRateDenominator()),
    minPersistentTTL: archival.minPersistentTtl(),
    maxInstructions: Number(compute.txMaxInstructions().toString()),
    maxReadEntries: cost.txMaxDiskReadEntries(),
    maxWriteEntries: cost.txMaxWriteLedgerEntries(),
    maxFootprint: ext.txMaxFootprintEntries(),
    maxReadBytes: cost.txMaxDiskReadBytes(),
    maxWrites: cost.txMaxWriteBytes(),
  };
}

// An account or a trustline, which the network reads from disk.
const classic = (k: xdr.LedgerKey): boolean => ["account", "trustline"].includes(k.switch().name);

function dataWith(
  data: xdr.SorobanTransactionData,
  footprint: xdr.LedgerFootprint,
  instructions: number,
  diskReadBytes: number,
  writeBytes: number,
): xdr.SorobanTransactionData {
  return new xdr.SorobanTransactionData({
    ext: data.ext(),
    resources: new xdr.SorobanResources({ footprint, instructions, diskReadBytes, writeBytes }),
    resourceFee: data.resourceFee(),
  });
}

// Adds x to simulated transaction data and returns it with the fee it adds: the network's fee for
// the entries, instructions, written bytes and transaction size it adds, all non-refundable, and
// the rent and event fee the other path may need, which is refunded when it goes unused. Entries
// are added in x's order; one a network limit has no room for is left out, and the call goes with
// less room than its other path may need. One already read-only moves to the read-write entries
// after those added.
function addExtra(
  data: xdr.SorobanTransactionData,
  x: Extra,
  c: LedgerCosts,
): { readonly data: xdr.SorobanTransactionData; readonly fee: bigint } {
  const resources = data.resources();
  const footprint = resources.footprint();
  const readOnly = [...footprint.readOnly()];
  const readWrite = [...footprint.readWrite()];
  const written = new Set(readWrite.map(keyId));
  const read = new Map(readOnly.map((k, i) => [keyId(k), i]));
  let reads = [...readOnly, ...readWrite].filter(classic).length;
  const promoted: number[] = [];
  let writes = 0n;
  let newReads = 0n;
  for (const key of x.readWrite) {
    const id = keyId(key);
    if (written.has(id)) continue;
    written.add(id);
    if (readWrite.length + promoted.length >= c.maxWriteEntries) continue;
    const at = read.get(id);
    if (at !== undefined) {
      promoted.push(at);
    } else {
      if (
        readOnly.length + readWrite.length >= c.maxFootprint ||
        (classic(key) && reads >= c.maxReadEntries)
      ) {
        continue;
      }
      readWrite.push(key);
      if (classic(key)) {
        reads++;
        newReads++;
      }
    }
    writes++;
  }
  promoted.sort((a, b) => a - b);
  promoted.forEach((i, j) => {
    readWrite.push(readOnly[i - j] as xdr.LedgerKey);
    readOnly.splice(i - j, 1);
  });
  const instructions = Math.min(
    resources.instructions() + x.instructions,
    Math.max(c.maxInstructions, resources.instructions()),
  );
  const writeBytes = Math.min(
    resources.writeBytes() + x.writeBytes,
    Math.max(c.maxWrites, resources.writeBytes()),
  );
  let fee =
    writes * c.writeEntry +
    newReads * c.readEntry +
    ceilDiv(BigInt(instructions) * c.instruction, 10_000n) -
    ceilDiv(BigInt(resources.instructions()) * c.instruction, 10_000n) +
    perKB(writeBytes, c.write1KB) -
    perKB(resources.writeBytes(), c.write1KB);
  const padded = dataWith(
    data,
    new xdr.LedgerFootprint({ readOnly, readWrite }),
    instructions,
    resources.diskReadBytes(),
    writeBytes,
  );
  const grown = padded.toXDR().length - data.toXDR().length;
  fee += perKB(grown, c.txSize1KB) + perKB(grown, c.historical1KB);
  if (x.newBytes > 0) {
    const ledgers = BigInt(Math.max(x.rentLedgers, c.minPersistentTTL));
    const denominator = c.rentDenominator > 1n ? c.rentDenominator : 1n;
    fee +=
      ceilDiv(BigInt(x.newBytes) * c.rent1KB * ledgers, 1024n * denominator) +
      c.writeEntry +
      perKB(TTL_ENTRY_BYTES, c.write1KB);
  }
  fee += perKB(x.eventBytes, c.events1KB);
  return { data: padded, fee };
}

// Adds CLASSIC_PAD to the bytes the call may read for each account or trustline in its footprint,
// and to the bytes it may write for each it writes, within the network's limits, and returns the
// data with the fee those bytes add.
function padClassic(
  data: xdr.SorobanTransactionData,
  c: LedgerCosts,
): { readonly data: xdr.SorobanTransactionData; readonly fee: bigint } {
  const resources = data.resources();
  const footprint = resources.footprint();
  const writes = footprint.readWrite().filter(classic).length;
  const reads = writes + footprint.readOnly().filter(classic).length;
  const read = Math.min(
    resources.diskReadBytes() + reads * CLASSIC_PAD,
    Math.max(c.maxReadBytes, resources.diskReadBytes()),
  );
  const write = Math.min(
    resources.writeBytes() + writes * CLASSIC_PAD,
    Math.max(c.maxWrites, resources.writeBytes()),
  );
  const fee =
    perKB(read - resources.diskReadBytes(), c.read1KB) +
    perKB(write - resources.writeBytes(), c.write1KB);
  return { data: dataWith(data, footprint, resources.instructions(), read, write), fee };
}

const invokeArgs = (contract: string, fn: string, args: readonly xdr.ScVal[]): string =>
  new xdr.InvokeContractArgs({
    contractAddress: new Address(contract).toScAddress(),
    functionName: fn,
    args: [...args],
  }).toXDR("base64");

function invocationArgs(invocation: xdr.SorobanAuthorizedInvocation): string {
  const fn = invocation.function();
  if (fn.switch().name !== "sorobanAuthorizedFunctionTypeContractFn") return "";
  return fn.contractFn().toXDR("base64");
}

// The simulation proposes the authorizations; a dishonest RPC could slip in one that moves the
// signer's funds elsewhere, so only the exact call and its expected transfers are accepted.
function checkAuth(
  entries: readonly xdr.SorobanAuthorizationEntry[],
  vault: string,
  call: VaultCall,
): void {
  const refuse = (): never =>
    fail("rpc_error", "the simulation asks for an authorization this call does not make");
  for (const entry of entries) {
    if (entry.credentials().switch().name !== "sorobanCredentialsSourceAccount") refuse();
    const root = entry.rootInvocation();
    if (invocationArgs(root) !== invokeArgs(vault, call.fn, call.args)) refuse();
    const expected = call.transfers.map((t) => invokeArgs(t.token, "transfer", t.args)).sort();
    const subs = root.subInvocations();
    if (subs.some((s) => s.subInvocations().length > 0)) refuse();
    const actual = subs.map(invocationArgs).sort();
    if (actual.length !== expected.length || actual.some((a, i) => a !== expected[i])) refuse();
  }
}

function signedEnvelope(value: unknown): string {
  if (typeof value === "string") return value;
  if (typeof value === "object" && value !== null) {
    const signed = (value as Record<string, unknown>)["signedTxXdr"];
    if (typeof signed === "string") return signed;
  }
  return fail("signer_mismatch", "the signer returned no transaction envelope");
}

function simulationFailure(code: number | undefined): CyphrasError {
  const name = code === undefined ? undefined : vaultErrorName(code);
  const what = name === undefined ? "the call" : `the call (${name})`;
  return new CyphrasError("transaction_failed", `the vault refuses ${what}`, {
    ...(code === undefined ? {} : { contractError: code }),
    ...(name === undefined ? {} : { vaultError: name }),
  });
}

// What a caller learns of each attempt of a call: its hash just before the signed envelope goes
// out, and again once the network has the transaction, before the wait for it.
export interface SubmitHooks {
  readonly onSending?: (hash: string) => Promise<void>;
  readonly onSubmitted?: (hash: string) => Promise<void>;
}

// Builds, simulates, signs and submits one vault call with the signer's account as source, then
// waits until the transaction is final. A transaction the network refused, or did not take before
// its time bound passed, fails with details.refused: it never lands.
export async function invokeVault(
  ctx: InvokeContext,
  signer: TransactionSigner,
  call: VaultCall,
  hooks: SubmitHooks = {},
): Promise<InvokeResult> {
  for (let attempt = 1; ; attempt++) {
    const outcome = await attemptCall(ctx, signer, call, hooks);
    if (outcome.result !== undefined) return outcome.result;
    const failed = (message: string, details: ErrorDetails = {}): CyphrasError =>
      new CyphrasError("transaction_failed", message, { hash: outcome.hash, ...details });
    // A call on the exit queue that failed on the host's storage touched an entry the queue moved
    // to past the room its footprint was given: a fresh simulation sees where it moved. With a
    // second provider, the first one's word alone does not send it again.
    if (call.extend === undefined || !outcome.conflict || attempt === ATTEMPTS) {
      throw failed("the transaction failed on chain");
    }
    const doubt = await secondDoubt(ctx, outcome.hash);
    if (doubt !== undefined) throw failed(DOUBTS[doubt], { secondProvider: doubt });
  }
}

// Why a second provider leaves a failure on the host's storage unconfirmed.
type Doubt = "no_answer" | "no_diagnostics" | "other_outcome";

const DOUBTS: Readonly<Record<Doubt, string>> = {
  no_answer: "the transaction failed on chain, and the second RPC provider did not report it",
  no_diagnostics:
    "the transaction failed on chain, and the second RPC provider returns no diagnostic events to show why; a provider that does is needed to send such a call again",
  other_outcome:
    "the transaction failed on chain, and the second RPC provider reports it otherwise",
};

// Why the second provider, when one is set, does not report the transaction failed on the host's
// storage as well; undefined when it does.
async function secondDoubt(ctx: InvokeContext, hash: string): Promise<Doubt | undefined> {
  if (ctx.second === undefined) return undefined;
  const [status] = await askTransaction(ctx, [ctx.second], hash);
  if (status === undefined || status.status === "NOT_FOUND") return "no_answer";
  if (status.status === "FAILED" && status.conflict) return undefined;
  return status.status === "FAILED" && !status.diagnosed ? "no_diagnostics" : "other_outcome";
}

// Asks every one of `providers` about a transaction, again while some do not hold it yet, within
// ASK_POLLS requests and ASK_MS in all: each one's status, undefined where it never answered.
export async function askTransaction(
  ctx: Pick<InvokeContext, "now" | "sleep">,
  providers: readonly SorobanRpc[],
  hash: string,
): Promise<(TransactionStatus | undefined)[]> {
  const deadline = ctx.now() + ASK_MS;
  const statuses: (TransactionStatus | undefined)[] = providers.map(() => undefined);
  const held = (s: TransactionStatus | undefined): boolean =>
    s !== undefined && s.status !== "NOT_FOUND";
  for (let poll = 1; ; poll++) {
    for (const [i, provider] of providers.entries()) {
      if (held(statuses[i])) continue;
      statuses[i] = await provider.getTransaction(hash, ASK_REQUEST_MS).catch((err: unknown) => {
        if (err instanceof CyphrasError) return undefined;
        throw err;
      });
    }
    if (statuses.every(held) || poll === ASK_POLLS || ctx.now() >= deadline) return statuses;
    await ctx.sleep(POLL_MS);
  }
}

// One attempt of a call: the landed transaction's result, or the hash of one that failed on chain
// and whether it failed on the host's storage.
async function attemptCall(
  ctx: InvokeContext,
  signer: TransactionSigner,
  call: VaultCall,
  hooks: SubmitHooks,
): Promise<{ readonly result?: InvokeResult; readonly hash: string; readonly conflict?: boolean }> {
  const sourceKey = accountKey(signer.publicKey);
  const { entries } = await ctx.rpc.getLedgerEntries([sourceKey]);
  const source = entries.get(keyId(sourceKey));
  if (source === undefined) fail("invalid_argument", "the signer's account does not exist");
  const sequence = source.data.account().seqNum().toString();
  const build = (
    fee: bigint,
    data?: xdr.SorobanTransactionData,
    auth?: xdr.SorobanAuthorizationEntry[],
  ): Transaction => {
    const options: TransactionBuilder.TransactionBuilderOptions = {
      fee: fee.toString(),
      networkPassphrase: ctx.networkPassphrase,
    };
    if (data !== undefined) options.sorobanData = data;
    const op = Operation.invokeContractFunction({
      contract: ctx.vault,
      function: call.fn,
      args: [...call.args],
      ...(auth === undefined ? {} : { auth }),
    });
    return new TransactionBuilder(new Account(signer.publicKey, sequence), options)
      .addOperation(op)
      .setTimeout(TIMEOUT_SECONDS)
      .build();
  };

  const draft = build(MIN_INCLUSION_FEE);
  const simulation = await ctx.rpc.simulateTransaction(draft.toEnvelope().toXDR("base64"));
  if (simulation.failed) throw simulationFailure(simulation.contractError);
  if (simulation.needsRestore) fail("rpc_error", "the call needs archived entries restored first");
  const auth = simulation.auth.map((a) => xdr.SorobanAuthorizationEntry.fromXDR(a, "base64"));
  checkAuth(auth, ctx.vault, call);
  const quoted = await ctx.rpc.sorobanInclusionFee().catch(() => MIN_INCLUSION_FEE);
  const inclusion = quoted > MIN_INCLUSION_FEE ? quoted : MIN_INCLUSION_FEE;
  let data = xdr.SorobanTransactionData.fromXDR(simulation.transactionData, "base64");
  if (call.extend !== undefined) {
    const costs = await ledgerCosts(ctx.rpc);
    const extended = addExtra(data, await call.extend(data.resources().footprint()), costs);
    const padded = padClassic(extended.data, costs);
    const total = BigInt(data.resourceFee().toString()) + extended.fee + padded.fee;
    data = padded.data;
    data.resourceFee(xdr.Int64.fromString(total.toString()));
  }
  // The padding's fees come from the network's settings as the RPC reports them, so the cap bounds
  // the whole fee.
  const resource = BigInt(data.resourceFee().toString());
  if (inclusion > ctx.feeCaps.inclusion || resource > ctx.feeCaps.resource) {
    fail("fee_above_cap", "the network fee is above the cap", {
      inclusion: inclusion.toString(),
      resource: resource.toString(),
    });
  }
  const fee: NetworkFee = { inclusion, resource, total: inclusion + resource };
  if (signer.confirmFee !== undefined && !(await signer.confirmFee(fee))) {
    fail("not_confirmed", "the network fee was not confirmed");
  }
  // The builder adds the resource fee of the Soroban data to the inclusion fee it is given.
  const tx = build(inclusion, data, auth);
  if (BigInt(tx.fee) !== fee.total) fail("rpc_error", "the transaction's fee is not the one shown");
  const hash = bytesToHex(Uint8Array.from(tx.hash()));

  const signedXdr = signedEnvelope(await signer.signTransaction(tx.toXDR(), ctx.networkPassphrase));
  let signed: Transaction | FeeBumpTransaction;
  try {
    signed = TransactionBuilder.fromXDR(signedXdr, ctx.networkPassphrase);
  } catch {
    return fail("signer_mismatch", "the signer returned an unreadable envelope");
  }
  // The signer may add signatures but not change the transaction.
  if (signed instanceof FeeBumpTransaction || bytesToHex(Uint8Array.from(signed.hash())) !== hash) {
    fail("signer_mismatch", "the signer returned a different transaction");
  }
  if (signed.signatures.length === 0) fail("signer_mismatch", "the transaction is not signed");

  const deadline = ctx.now() + (TIMEOUT_SECONDS + 30) * 1000;
  let backoff = POLL_MS;
  await hooks.onSending?.(hash);
  for (;;) {
    const sent = await ctx.rpc.sendTransaction(signedXdr);
    if (sent.hash !== hash) fail("rpc_error", "the RPC reports a different transaction hash");
    if (sent.status === "PENDING" || sent.status === "DUPLICATE") break;
    if (sent.status === "ERROR") {
      fail("transaction_failed", "the network refused the transaction", { hash, refused: true });
    }
    // TRY_AGAIN_LATER: the same signed envelope goes again until its time bound passes.
    if (ctx.now() > deadline) {
      fail("transaction_failed", "the network did not take the transaction", {
        hash,
        refused: true,
      });
    }
    await ctx.sleep(backoff);
    backoff = Math.min(backoff * 2, 30_000);
  }
  await hooks.onSubmitted?.(hash);
  for (;;) {
    const status = await ctx.rpc.getTransaction(hash);
    if (status.status === "SUCCESS") {
      const ledger = status.ledger ?? status.latestLedger;
      return {
        hash,
        result: { hash, ledger, returnValue: status.returnValue, events: status.events },
      };
    }
    if (status.status === "FAILED") return { hash, conflict: status.conflict };
    if (ctx.now() > deadline) {
      throw new CyphrasError("transaction_failed", "the transaction expired unconfirmed", { hash });
    }
    await ctx.sleep(POLL_MS);
  }
}
