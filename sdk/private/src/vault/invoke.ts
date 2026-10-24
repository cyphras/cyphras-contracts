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
import { CyphrasError, type ErrorDetails, fail, isDeclinedSignature } from "../errors.ts";
import {
  type LedgerEntries,
  type LedgerEntry,
  type MetaEvent,
  type SorobanRpc,
  type TransactionStatus,
  isPersistent,
  keyId,
} from "../net/rpc.ts";
import { vaultErrorName } from "./errors.ts";
import { accountKey } from "./state.ts";

/**
 * What a transaction's resource fee pays for beyond the network's own fees: "restore" when it
 * brings archived entries back, "rent" when it renews vault entries close to archival, for the time
 * since they were last extended.
 */
export type FeeReason = "network" | "restore" | "rent";

/** The network fee of a Stellar transaction the SDK built, in stroops. */
export interface NetworkFee {
  // What the transaction bids for inclusion, and what its simulated resources cost.
  readonly inclusion: bigint;
  readonly resource: bigint;
  readonly total: bigint;
  // Why the resource fee is what it is, and the entries it restores or renews, by name.
  readonly reason: FeeReason;
  readonly entries: readonly string[];
}

/** The most the SDK lets a transaction it builds pay, in stroops. */
export interface NetworkFeeCaps {
  readonly inclusion: bigint;
  readonly resource: bigint;
  // What a transaction that restores or renews entries may pay above `resource`.
  readonly restore: bigint;
}

export const DEFAULT_NETWORK_FEE_CAPS: NetworkFeeCaps = {
  inclusion: 100_000n,
  resource: 10_000_000n,
  restore: 0n,
};

// The most a transaction envelope's fee field holds, in stroops.
const MAX_ENVELOPE_FEE = 4_294_967_295n;

// Caps a caller gives, checked: each present one a bigint of at least 0, the inclusion cap within
// what an envelope holds. Caps left undefined are dropped, so they keep the caps they would replace.
export function feeCapsOf(caps: unknown): Partial<NetworkFeeCaps> {
  if (caps === undefined) return {};
  if (typeof caps !== "object" || caps === null) {
    fail("invalid_argument", "network fee caps are an object of bigints");
  }
  const out: { -readonly [K in keyof NetworkFeeCaps]?: bigint } = {};
  for (const [name, value] of Object.entries(caps)) {
    if (name !== "inclusion" && name !== "resource" && name !== "restore") {
      fail("invalid_argument", `there is no network fee cap ${name}`);
    }
    if (value === undefined) continue;
    if (typeof value !== "bigint" || value < 0n) {
      fail("invalid_argument", `the network fee cap ${name} is not a bigint of at least 0`);
    }
    if (name === "inclusion" && value > MAX_ENVELOPE_FEE) {
      fail("invalid_argument", "the inclusion fee cap is above what a transaction carries");
    }
    out[name] = value;
  }
  return out;
}

/** What a restore of the vault's entries did: its transaction, when one was needed, and the entries it restored, by name. */
export interface VaultRestore {
  readonly txHash: string | undefined;
  readonly restored: readonly string[];
}

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
// transfers it may make from the signer's account. A call on one of the vault's queues, whose path
// the vault decides in the ledger it lands in, names what it may need beyond its simulation, from
// the footprint the simulation found; another transaction in the same ledger can still move the
// queue past it, and such a call that fails on the host's storage goes again after a fresh
// simulation, at most `attempts` times in all.
export interface VaultCall {
  readonly fn: string;
  readonly args: readonly xdr.ScVal[];
  readonly transfers: readonly { readonly token: string; readonly args: readonly xdr.ScVal[] }[];
  readonly extend?: (footprint: xdr.LedgerFootprint) => Promise<Extra>;
  readonly attempts?: number;
}

export interface InvokeContext {
  readonly rpc: SorobanRpc;
  // A second provider, which must report a failure on the host's storage too before a call goes
  // again.
  readonly second: SorobanRpc | undefined;
  readonly networkPassphrase: string;
  readonly vault: string;
  // The pinned vault wasm and pool asset contract: the only code and the only other contract
  // whose archived entries a call restores.
  readonly vaultWasmHash: string;
  readonly asset: string;
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
// How often a call on one of the vault's queues goes in all while it fails on the host's storage,
// where the call itself names no other count.
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
// The TTL in ledgers under which the vault extends its instance, with its code, and its tree when a
// call writes them, so that the call pays their rent for the time since they were last extended.
const VAULT_TTL_THRESHOLD = 30 * 17_280;
// The entries whose rent every call of the vault may pay.
const RENEWED = new Set(["code", "instance", "Roots", "Frontier", "NextLeaf"]);
// No more ledgers than this close before a transaction's time bound passes: one a second, five
// times the nominal rate.
const BOUND_LEDGERS = TIMEOUT_SECONDS;
// A call that met an archival edge, dropped at its ledger bound or failed on an archived entry it
// did not restore, goes once more after a fresh simulation.
const ARCHIVAL_RETRIES = 1;
// The keys one getLedgerEntries request takes at most.
const MAX_KEYS = 200;

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
  ext: xdr.SorobanTransactionDataExt = data.ext(),
): xdr.SorobanTransactionData {
  return new xdr.SorobanTransactionData({
    ext,
    resources: new xdr.SorobanResources({ footprint, instructions, diskReadBytes, writeBytes }),
    resourceFee: data.resourceFee(),
  });
}

// Adds x to simulated transaction data and returns it with the fee it adds: the network's fee for
// the entries, instructions, read and written bytes and transaction size it adds, all
// non-refundable, and the rent and event fee the other path may need, which is refunded when it
// goes unused. Entries are added in x's order; one a network limit has no room for is left out,
// and the call goes with less room than its other path may need. One already read-only moves to
// the read-write entries after those added. An added entry among `archived`, by key with its bytes,
// is marked for the network to restore, which reads it from disk, writes it and charges its rent
// for the network's least TTL of a restored entry, or for x's rent ledgers if that is longer.
function addExtra(
  data: xdr.SorobanTransactionData,
  x: Extra,
  c: LedgerCosts,
  archived: ReadonlyMap<string, number>,
): { readonly data: xdr.SorobanTransactionData; readonly fee: bigint } {
  const resources = data.resources();
  const footprint = resources.footprint();
  const readOnly = [...footprint.readOnly()];
  const readWrite = [...footprint.readWrite()];
  const written = new Set(readWrite.map(keyId));
  const read = new Map(readOnly.map((k, i) => [keyId(k), i]));
  let reads = [...readOnly, ...readWrite].filter(classic).length + marks(data).length;
  const promoted: number[] = [];
  const restored: number[] = [];
  let writes = 0n;
  let newReads = 0n;
  for (const key of x.readWrite) {
    const id = keyId(key);
    if (written.has(id)) continue;
    written.add(id);
    if (readWrite.length + promoted.length >= c.maxWriteEntries) continue;
    const at = read.get(id);
    const bytes = archived.get(id);
    if (at !== undefined) {
      promoted.push(at);
    } else {
      if (
        readOnly.length + readWrite.length >= c.maxFootprint ||
        ((classic(key) || bytes !== undefined) && reads >= c.maxReadEntries)
      ) {
        continue;
      }
      if (bytes !== undefined) restored.push(bytes);
      readWrite.push(key);
      if (classic(key) || bytes !== undefined) {
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
  // Added entries follow the simulated ones, so the simulation's marks keep their entries.
  const indices = [...marks(data)];
  readWrite.forEach((k, i) => {
    if (i >= footprint.readWrite().length && archived.has(keyId(k))) indices.push(i);
  });
  const restoredBytes = restored.reduce((sum, b) => sum + b, 0);
  const instructions = Math.min(
    resources.instructions() + x.instructions,
    Math.max(c.maxInstructions, resources.instructions()),
  );
  const diskReadBytes = Math.min(
    resources.diskReadBytes() + restoredBytes,
    Math.max(c.maxReadBytes, resources.diskReadBytes()),
  );
  const writeBytes = Math.min(
    resources.writeBytes() + x.writeBytes + restoredBytes,
    Math.max(c.maxWrites, resources.writeBytes()),
  );
  let fee =
    writes * c.writeEntry +
    newReads * c.readEntry +
    ceilDiv(BigInt(instructions) * c.instruction, 10_000n) -
    ceilDiv(BigInt(resources.instructions()) * c.instruction, 10_000n) +
    perKB(diskReadBytes, c.read1KB) -
    perKB(resources.diskReadBytes(), c.read1KB) +
    perKB(writeBytes, c.write1KB) -
    perKB(resources.writeBytes(), c.write1KB);
  const padded = dataWith(
    data,
    new xdr.LedgerFootprint({ readOnly, readWrite }),
    instructions,
    diskReadBytes,
    writeBytes,
    indices.length === 0
      ? data.ext()
      : new xdr.SorobanTransactionDataExt(
          1,
          new xdr.SorobanResourcesExtV0({ archivedSorobanEntries: indices }),
        ),
  );
  const grown = padded.toXDR().length - data.toXDR().length;
  fee += perKB(grown, c.txSize1KB) + perKB(grown, c.historical1KB);
  const ledgers = BigInt(Math.max(x.rentLedgers, c.minPersistentTTL));
  const denominator = c.rentDenominator > 1n ? c.rentDenominator : 1n;
  const rent = (bytes: number): bigint =>
    ceilDiv(BigInt(bytes) * c.rent1KB * ledgers, 1024n * denominator) +
    c.writeEntry +
    perKB(TTL_ENTRY_BYTES, c.write1KB);
  if (x.newBytes > 0) fee += rent(x.newBytes);
  for (const bytes of restored) fee += rent(bytes);
  fee += perKB(x.eventBytes, c.events1KB);
  return { data: padded, fee };
}

// The indices of the read-write entries that transaction data marks for the network to restore.
const marks = (data: xdr.SorobanTransactionData): number[] =>
  data.ext().switch() === 1 ? data.ext().resourceExt().archivedSorobanEntries() : [];

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

type Owners = Pick<InvokeContext, "vault" | "vaultWasmHash" | "asset">;

// A ledger entry by its owner and the name it is keyed with, as a fee shows it: the vault's code
// and entries by name alone, the pool asset contract's after "asset", any other by its contract
// address or code hash.
function entryName(key: xdr.LedgerKey, o: Owners): string {
  const kind = key.switch().name;
  if (kind === "contractCode") {
    const hash = bytesToHex(Uint8Array.from(key.contractCode().hash()));
    return hash === o.vaultWasmHash ? "code" : `code ${hash}`;
  }
  if (kind !== "contractData") return kind;
  const data = key.contractData();
  const contract = Address.fromScAddress(data.contract()).toString();
  const owner = contract === o.vault ? "" : contract === o.asset ? "asset " : `${contract} `;
  const k = data.key();
  if (k.switch().name === "scvLedgerKeyContractInstance") return `${owner}instance`;
  const first = k.switch().name === "scvVec" ? k.vec()?.[0] : undefined;
  return owner + (first?.switch().name === "scvSymbol" ? first.sym().toString() : "data");
}

const entryNames = (keys: readonly xdr.LedgerKey[], o: Owners): string[] => [
  ...new Set(keys.map((k) => entryName(k, o))),
];

// An entry a vault call may restore: the pinned vault code, a persistent entry of the vault, or
// the pool asset contract's instance or a balance in it.
function restorable(key: xdr.LedgerKey, o: Owners): boolean {
  if (!isPersistent(key)) return false;
  const name = entryName(key, o);
  if (key.switch().name === "contractCode") return name === "code";
  const contract = Address.fromScAddress(key.contractData().contract()).toString();
  return contract === o.vault || name === "asset instance" || name === "asset Balance";
}

// The vault's entries of one nullifier, deposit or exit. A call's simulation restores those it
// needs; one that archives while the call is on its way fails the call, which goes once more.
const PER_ITEM = new Set(["Nullifier", "Pending", "Exit", "Stranded"]);

// A persistent entry other than the vault's per-item ones, such as its code, instance and tree, or
// a balance in the asset contract. A call reads their TTLs, so that their archival edge drops it
// unpaid.
const bounded = (key: xdr.LedgerKey, o: Owners): boolean =>
  isPersistent(key) && !PER_ITEM.has(entryName(key, o));

// An entry the network holds archived as of `latest`, its TTL at or before that ledger: it can come
// back only by a restore.
const archivedBy = (entry: LedgerEntry, latest: number): boolean =>
  entry.liveUntilLedger !== undefined && entry.liveUntilLedger <= latest;

// The bytes the network reads from disk and writes for a restored entry: its key and its entry.
const entryBytes = (entry: LedgerEntry): number =>
  entry.key.toXDR().length +
  new xdr.LedgerEntry({
    lastModifiedLedgerSeq: entry.lastModifiedLedger,
    data: entry.data,
    ext: new xdr.LedgerEntryExt(0),
  }).toXDR().length;

// The entries of `keys`, read at most MAX_KEYS at a time, and the earliest ledger of those reads.
async function readEntries(
  rpc: SorobanRpc,
  keys: readonly xdr.LedgerKey[],
): Promise<LedgerEntries> {
  const unique = [...new Map(keys.map((k) => [keyId(k), k])).values()];
  const entries = new Map<string, LedgerEntry>();
  let latestLedger = 0;
  for (let i = 0; i < unique.length; i += MAX_KEYS) {
    const read = await rpc.getLedgerEntries(unique.slice(i, i + MAX_KEYS));
    read.entries.forEach((entry, id) => entries.set(id, entry));
    latestLedger = i === 0 ? read.latestLedger : Math.min(latestLedger, read.latestLedger);
  }
  return { latestLedger, entries };
}

// The fee shown for a transaction, refused above what an envelope carries, whatever the caps, and
// above the caps: a restore or a renewal may take the caps' room for a restore beyond the resource
// cap.
function checkFee(
  caps: NetworkFeeCaps,
  inclusion: bigint,
  resource: bigint,
  reason: FeeReason,
  entries: readonly string[],
): NetworkFee {
  const details = {
    inclusion: inclusion.toString(),
    resource: resource.toString(),
    reason,
    ...(entries.length === 0 ? {} : { entries: entries.join(",") }),
  };
  if (inclusion + resource > MAX_ENVELOPE_FEE) {
    fail("fee_above_limit", "the network fee is above what one transaction carries", {
      ...details,
      limit: MAX_ENVELOPE_FEE.toString(),
    });
  }
  const room = reason === "network" ? caps.resource : caps.resource + caps.restore;
  if (inclusion > caps.inclusion || resource > room) {
    fail("fee_above_cap", "the network fee is above the cap", details);
  }
  return { inclusion, resource, total: inclusion + resource, reason, entries };
}

async function sequenceOf(rpc: SorobanRpc, account: string): Promise<string> {
  const sourceKey = accountKey(account);
  const { entries } = await rpc.getLedgerEntries([sourceKey]);
  const source = entries.get(keyId(sourceKey));
  if (source === undefined) fail("invalid_argument", "the signer's account does not exist");
  return source.data.account().seqNum().toString();
}

async function inclusionFee(rpc: SorobanRpc): Promise<bigint> {
  const quoted = await rpc.sorobanInclusionFee().catch(() => MIN_INCLUSION_FEE);
  return quoted > MIN_INCLUSION_FEE ? quoted : MIN_INCLUSION_FEE;
}

function signedEnvelope(value: unknown): string {
  if (isDeclinedSignature(value, "signedTxXdr")) {
    return fail("signer_rejected", "the signer declined to sign the transaction");
  }
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

// What a caller learns of each attempt of a call: that the signer is asked to sign it; its hash
// just before the signed envelope goes out, and again once the network has the transaction, before
// the wait for it; and the hash of one the network can no longer take, past its ledger bound.
export interface SubmitHooks {
  readonly onSigning?: () => void;
  readonly onSending?: (hash: string) => Promise<void>;
  readonly onSubmitted?: (hash: string) => Promise<void>;
  readonly onDropped?: (hash: string) => Promise<void>;
}

// Builds, simulates, signs and submits one vault call with the signer's account as source, then
// waits until the transaction is final. A transaction the RPC reports the network refused, or did
// not take before its time bound passed, fails with details.refused. The call restores the
// archived entries its simulation marks, within the caps' room for a restore; when the RPC asks
// for a RestoreFootprint transaction first, the signer sends that one before the call, and a
// failed one fails with restore_failed.
export async function invokeVault(
  ctx: InvokeContext,
  signer: TransactionSigner,
  call: VaultCall,
  hooks: SubmitHooks = {},
): Promise<InvokeResult> {
  let conflicts = 0;
  let edges = 0;
  let restored = false;
  // A restore the call needed first takes its fee from the call's room for a restore.
  let caps = ctx.feeCaps;
  for (;;) {
    const outcome = await attemptCall({ ...ctx, feeCaps: caps }, signer, call, hooks);
    if (outcome.kind === "landed") return outcome.result;
    if (outcome.kind === "restore") {
      if (restored) fail("rpc_error", "the call still needs a restore after one landed");
      restored = true;
      const spent = await restoreFootprint({ ...ctx, feeCaps: caps }, signer, outcome.data);
      caps = { ...caps, restore: caps.restore > spent ? caps.restore - spent : 0n };
      continue;
    }
    // An entry of the call archived after its simulation saw it live: the transaction was dropped
    // at its ledger bound, or failed on the entry, and a fresh simulation restores it. With a
    // second provider, the first one's word alone does not send it again.
    if (outcome.kind === "dropped" || outcome.archived) {
      if (outcome.hash !== undefined && ctx.second !== undefined) {
        const [status] = await askTransaction(ctx, [ctx.second], outcome.hash);
        const confirmed =
          outcome.kind === "dropped"
            ? status?.status === "NOT_FOUND" && status.latestLedger + 1 >= outcome.maxLedger
            : status?.status === "FAILED" && status.archived;
        if (!confirmed) {
          fail(
            "transaction_failed",
            "the transaction met an archived entry, and the second RPC provider reports it otherwise",
            { hash: outcome.hash, archived: true, secondProvider: "other_outcome" },
          );
        }
      }
      if (outcome.kind === "dropped" && outcome.hash !== undefined) {
        await hooks.onDropped?.(outcome.hash);
      }
      if (edges === ARCHIVAL_RETRIES) {
        if (outcome.hash === undefined) {
          fail(
            "rpc_error",
            "the RPC reports an entry archived that the simulation does not restore",
          );
        }
        fail(
          "transaction_failed",
          outcome.kind === "dropped"
            ? "the network did not take the transaction before its ledger bound"
            : "the transaction failed on chain on an archived entry",
          {
            hash: outcome.hash,
            archived: true,
            ...(outcome.kind === "dropped" ? { refused: true } : {}),
          },
        );
      }
      edges++;
      continue;
    }
    const hash = outcome.hash;
    const failed = (message: string, details: ErrorDetails = {}): CyphrasError =>
      new CyphrasError("transaction_failed", message, { hash, ...details });
    // A call on one of the vault's queues that failed on the host's storage touched an entry the
    // queue moved to past the room its footprint was given: a fresh simulation sees where it moved.
    // With a second provider, the first one's word alone does not send it again.
    if (call.extend === undefined || !outcome.conflict) {
      throw failed("the transaction failed on chain");
    }
    conflicts++;
    if (conflicts === (call.attempts ?? ATTEMPTS)) {
      throw failed("the transaction failed on chain", { conflict: true });
    }
    const doubt = await secondDoubt(ctx, hash);
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

// What became of one attempt of a call: its landed transaction's result; the hash of one that
// failed on chain, and whether it failed on the host's storage or on an archived entry; one the
// network can no longer take, past the ledger bound an archival edge set, with its hash once it was
// sent; or the RestoreFootprint transaction the RPC asks to land first.
type Attempt =
  | { readonly kind: "landed"; readonly result: InvokeResult }
  | {
      readonly kind: "failed";
      readonly hash: string;
      readonly conflict: boolean;
      readonly archived: boolean;
    }
  | { readonly kind: "dropped"; readonly hash: undefined }
  | { readonly kind: "dropped"; readonly hash: string; readonly maxLedger: number }
  | { readonly kind: "restore"; readonly data: xdr.SorobanTransactionData };

async function attemptCall(
  ctx: InvokeContext,
  signer: TransactionSigner,
  call: VaultCall,
  hooks: SubmitHooks,
): Promise<Attempt> {
  const sequence = await sequenceOf(ctx.rpc, signer.publicKey);
  const build = (
    fee: bigint,
    data?: xdr.SorobanTransactionData,
    auth?: xdr.SorobanAuthorizationEntry[],
    maxLedger?: number,
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
    const builder = new TransactionBuilder(new Account(signer.publicKey, sequence), options)
      .addOperation(op)
      .setTimeout(TIMEOUT_SECONDS);
    if (maxLedger !== undefined) builder.setLedgerbounds(0, maxLedger);
    return builder.build();
  };

  const draft = build(MIN_INCLUSION_FEE);
  const simulation = await ctx.rpc.simulateTransaction(draft.toEnvelope().toXDR("base64"));
  if (simulation.failed) throw simulationFailure(simulation.contractError);
  let data = xdr.SorobanTransactionData.fromXDR(simulation.transactionData, "base64");
  const simulated = data.resources().footprint();
  const inFootprint = [...simulated.readOnly(), ...simulated.readWrite()];
  // An RPC chooses what a restore covers, so the SDK takes only the call's own entries of the
  // vault and the pool asset, never another contract's at the signer's cost.
  const known = new Set(inFootprint.map(keyId));
  const own = (k: xdr.LedgerKey): boolean => known.has(keyId(k)) && restorable(k, ctx);
  if (!simulation.archived.every(own)) {
    fail("rpc_error", "the simulation restores entries that are not the call's own");
  }
  if (simulation.restorePreamble !== undefined) {
    const preamble = simulation.restorePreamble.transactionData;
    if (!preamble.resources().footprint().readWrite().every(own)) {
      fail("rpc_error", "the restore the RPC asks for names entries that are not the call's own");
    }
    return { kind: "restore", data: preamble };
  }
  const auth = simulation.auth.map((a) => xdr.SorobanAuthorizationEntry.fromXDR(a, "base64"));
  checkAuth(auth, ctx.vault, call);
  const inclusion = await inclusionFee(ctx.rpc);
  const extra = call.extend === undefined ? undefined : await call.extend(simulated);
  const lives = await readEntries(
    ctx.rpc,
    [...inFootprint, ...(extra?.readWrite ?? [])].filter((k) => bounded(k, ctx)),
  );
  // An entry the other path adds that is archived lies outside what the simulation restores, so
  // the call marks it itself.
  const restoring = new Map<string, number>();
  if (extra !== undefined) {
    for (const key of extra.readWrite) {
      const entry = lives.entries.get(keyId(key));
      if (
        entry !== undefined &&
        !known.has(keyId(key)) &&
        restorable(key, ctx) &&
        archivedBy(entry, lives.latestLedger)
      ) {
        restoring.set(keyId(key), entryBytes(entry));
      }
    }
    const costs = await ledgerCosts(ctx.rpc);
    const extended = addExtra(data, extra, costs, restoring);
    const padded = padClassic(extended.data, costs);
    const total = BigInt(data.resourceFee().toString()) + extended.fee + padded.fee;
    data = padded.data;
    data.resourceFee(xdr.Int64.fromString(total.toString()));
  }
  const footprint = data.resources().footprint();
  const restored = [
    ...simulation.archived,
    ...footprint.readWrite().filter((k) => restoring.has(keyId(k))),
  ];
  const marked = new Set(restored.map(keyId));
  const live = [...footprint.readOnly(), ...footprint.readWrite()].flatMap((key) => {
    const until = lives.entries.get(keyId(key))?.liveUntilLedger;
    return until === undefined || marked.has(keyId(key)) ? [] : [{ key, until }];
  });
  // A call that would land after an entry it reads archives is bound to the ledgers before that,
  // so that the network drops it unpaid rather than fail it on the entry.
  const low = live.length === 0 ? undefined : Math.min(...live.map((l) => l.until));
  if (low !== undefined && low <= lives.latestLedger) return { kind: "dropped", hash: undefined };
  const maxLedger =
    low !== undefined && low <= lives.latestLedger + BOUND_LEDGERS ? low + 1 : undefined;
  const renewed = live
    .filter((l) => l.until - lives.latestLedger < VAULT_TTL_THRESHOLD)
    .map((l) => l.key)
    .filter((k) => RENEWED.has(entryName(k, ctx)));
  const reason: FeeReason =
    restored.length > 0 ? "restore" : renewed.length > 0 ? "rent" : "network";
  // The padding's fees come from the network's settings as the RPC reports them, so the cap bounds
  // the whole fee.
  const fee = checkFee(
    ctx.feeCaps,
    inclusion,
    BigInt(data.resourceFee().toString()),
    reason,
    entryNames(reason === "restore" ? restored : reason === "rent" ? renewed : [], ctx),
  );
  const sent = await submit(
    ctx,
    signer,
    build(inclusion, data, auth, maxLedger),
    fee,
    hooks,
    maxLedger,
  );
  if (sent.kind === "dropped")
    return { kind: "dropped", hash: sent.hash, maxLedger: maxLedger ?? 0 };
  const { hash, status } = sent;
  if (sent.kind === "failed") {
    return { kind: "failed", hash, conflict: status.conflict, archived: status.archived };
  }
  const ledger = status.ledger ?? status.latestLedger;
  return {
    kind: "landed",
    result: { hash, ledger, returnValue: status.returnValue, events: status.events },
  };
}

// A signed transaction the network took and that is final, or that it can no longer take, past its
// ledger bound.
type Sent =
  | {
      readonly kind: "landed" | "failed";
      readonly hash: string;
      readonly status: TransactionStatus;
    }
  | { readonly kind: "dropped"; readonly hash: string };

// Shows the fee to the signer, has it sign the transaction, sends the signed envelope and waits
// until the transaction is final.
async function submit(
  ctx: Pick<InvokeContext, "rpc" | "networkPassphrase" | "now" | "sleep">,
  signer: TransactionSigner,
  tx: Transaction,
  fee: NetworkFee,
  hooks: SubmitHooks,
  maxLedger: number | undefined,
): Promise<Sent> {
  if (signer.confirmFee !== undefined && !(await signer.confirmFee(fee))) {
    fail("not_confirmed", "the network fee was not confirmed");
  }
  // The builder adds the resource fee of the Soroban data to the inclusion fee it is given.
  if (BigInt(tx.fee) !== fee.total) fail("rpc_error", "the transaction's fee is not the one shown");
  const hash = bytesToHex(Uint8Array.from(tx.hash()));

  hooks.onSigning?.();
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
  // Once the RPC holds the last ledger a bound transaction could land in, it can land no more.
  const past = (latest: number | undefined): boolean =>
    maxLedger !== undefined && latest !== undefined && latest + 1 >= maxLedger;
  let backoff = POLL_MS;
  await hooks.onSending?.(hash);
  for (;;) {
    const sent = await ctx.rpc.sendTransaction(signedXdr);
    if (sent.hash !== hash) fail("rpc_error", "the RPC reports a different transaction hash");
    if (sent.status === "PENDING" || sent.status === "DUPLICATE") break;
    if (sent.status === "ERROR") {
      if (past(sent.latestLedger)) return { kind: "dropped", hash };
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
    if (status.status === "SUCCESS") return { kind: "landed", hash, status };
    if (status.status === "FAILED") return { kind: "failed", hash, status };
    if (past(status.latestLedger)) return { kind: "dropped", hash };
    if (ctx.now() > deadline) {
      throw new CyphrasError("transaction_failed", "the transaction expired unconfirmed", { hash });
    }
    await ctx.sleep(POLL_MS);
  }
}

type RestoreContext = Omit<InvokeContext, "second">;

// Restores the read-write entries of `data` with a RestoreFootprint transaction the signer sends
// and pays for, within the caps' room for a restore, and returns its resource fee once it landed.
async function restoreFootprint(
  ctx: RestoreContext,
  signer: TransactionSigner,
  data: xdr.SorobanTransactionData,
): Promise<bigint> {
  return (await restoreSent(ctx, signer, data)).resource;
}

async function restoreSent(
  ctx: RestoreContext,
  signer: TransactionSigner,
  data: xdr.SorobanTransactionData,
): Promise<{ readonly hash: string; readonly resource: bigint }> {
  const footprint = data.resources().footprint();
  const keys = footprint.readWrite();
  if (footprint.readOnly().length > 0 || keys.length === 0 || !keys.every(isPersistent)) {
    fail("rpc_error", "the restore the RPC asks for names entries no restore takes");
  }
  const sequence = await sequenceOf(ctx.rpc, signer.publicKey);
  const inclusion = await inclusionFee(ctx.rpc);
  const resource = BigInt(data.resourceFee().toString());
  const fee = checkFee(ctx.feeCaps, inclusion, resource, "restore", entryNames(keys, ctx));
  const tx = new TransactionBuilder(new Account(signer.publicKey, sequence), {
    fee: inclusion.toString(),
    networkPassphrase: ctx.networkPassphrase,
    sorobanData: data,
  })
    .addOperation(Operation.restoreFootprint({}))
    .setTimeout(TIMEOUT_SECONDS)
    .build();
  let sent: Sent;
  try {
    sent = await submit(ctx, signer, tx, fee, {}, undefined);
  } catch (err) {
    if (err instanceof CyphrasError && err.code === "transaction_failed") {
      throw new CyphrasError("restore_failed", err.message, err.details);
    }
    throw err;
  }
  if (sent.kind !== "landed") {
    fail("restore_failed", "the restore failed on chain", { hash: sent.hash });
  }
  return { hash: sent.hash, resource };
}

// Restores those of `keys` that are archived with one RestoreFootprint transaction the signer sends
// and pays for, within the caps' room for a restore. Entries that are live, or missing, are left as
// they are; with none archived, nothing is sent.
export async function restoreEntries(
  ctx: RestoreContext,
  signer: TransactionSigner,
  keys: readonly xdr.LedgerKey[],
): Promise<VaultRestore> {
  const { entries, latestLedger } = await readEntries(ctx.rpc, keys);
  const archived = keys.filter((k) => {
    const entry = entries.get(keyId(k));
    return entry !== undefined && isPersistent(k) && archivedBy(entry, latestLedger);
  });
  if (archived.length === 0) return { txHash: undefined, restored: [] };
  const sequence = await sequenceOf(ctx.rpc, signer.publicKey);
  const draft = new TransactionBuilder(new Account(signer.publicKey, sequence), {
    fee: MIN_INCLUSION_FEE.toString(),
    networkPassphrase: ctx.networkPassphrase,
    sorobanData: new xdr.SorobanTransactionData({
      ext: new xdr.SorobanTransactionDataExt(0),
      resources: new xdr.SorobanResources({
        footprint: new xdr.LedgerFootprint({ readOnly: [], readWrite: archived }),
        instructions: 0,
        diskReadBytes: 0,
        writeBytes: 0,
      }),
      resourceFee: xdr.Int64.fromString("0"),
    }),
  })
    .addOperation(Operation.restoreFootprint({}))
    .setTimeout(TIMEOUT_SECONDS)
    .build();
  const simulation = await ctx.rpc.simulateTransaction(draft.toEnvelope().toXDR("base64"));
  if (simulation.failed) fail("rpc_error", "the RPC could not simulate the restore");
  const data = xdr.SorobanTransactionData.fromXDR(simulation.transactionData, "base64");
  const asked = new Set(archived.map(keyId));
  const restoring = data.resources().footprint().readWrite();
  if (!restoring.every((k) => asked.has(keyId(k)))) {
    fail("rpc_error", "the simulation restores entries the restore did not name");
  }
  // Entries restored since the read leave nothing to restore.
  if (restoring.length === 0) return { txHash: undefined, restored: [] };
  return {
    txHash: (await restoreSent(ctx, signer, data)).hash,
    restored: entryNames(restoring, ctx),
  };
}
