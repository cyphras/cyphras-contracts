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
import { CyphrasError, fail } from "../errors.ts";
import { type MetaEvent, type SorobanRpc, keyId } from "../net/rpc.ts";
import { vaultErrorName } from "./errors.ts";
import { accountKey } from "./state.ts";

/**
 * A Stellar wallet that signs transactions, in the shape wallets already expose. The result is
 * the signed transaction envelope as base64 XDR, or an object carrying it as `signedTxXdr`.
 */
export interface TransactionSigner {
  readonly publicKey: string;
  signTransaction(xdr: string, networkPassphrase: string): Promise<unknown>;
}

// A call the signer authorizes as the transaction source: the vault function, and the token
// transfers it may make from the signer's account.
export interface VaultCall {
  readonly fn: string;
  readonly args: readonly xdr.ScVal[];
  readonly transfers: readonly { readonly token: string; readonly args: readonly xdr.ScVal[] }[];
}

export interface InvokeContext {
  readonly rpc: SorobanRpc;
  readonly networkPassphrase: string;
  readonly vault: string;
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

// Builds, simulates, signs and submits one vault call with the signer's account as source, then
// waits until the transaction is final. `onSubmitted` runs with the hash once the network
// has the transaction, before the wait.
export async function invokeVault(
  ctx: InvokeContext,
  signer: TransactionSigner,
  call: VaultCall,
  onSubmitted: (hash: string) => Promise<void> = async () => {},
): Promise<InvokeResult> {
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
  const inclusion = await ctx.rpc.sorobanInclusionFee().catch(() => MIN_INCLUSION_FEE);
  const fee =
    (inclusion > MIN_INCLUSION_FEE ? inclusion : MIN_INCLUSION_FEE) + simulation.minResourceFee;
  const data = xdr.SorobanTransactionData.fromXDR(simulation.transactionData, "base64");
  const tx = build(fee, data, auth);
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

  const deadline = Date.now() + (TIMEOUT_SECONDS + 30) * 1000;
  let backoff = POLL_MS;
  for (;;) {
    const sent = await ctx.rpc.sendTransaction(signedXdr);
    if (sent.hash !== hash) fail("rpc_error", "the RPC reports a different transaction hash");
    if (sent.status === "PENDING" || sent.status === "DUPLICATE") break;
    if (sent.status === "ERROR") {
      fail("transaction_failed", "the network refused the transaction");
    }
    // TRY_AGAIN_LATER: the same signed envelope goes again until its time bound passes.
    if (Date.now() > deadline)
      fail("transaction_failed", "the network did not take the transaction");
    await ctx.sleep(backoff);
    backoff = Math.min(backoff * 2, 30_000);
  }
  await onSubmitted(hash);
  for (;;) {
    const status = await ctx.rpc.getTransaction(hash);
    if (status.status === "SUCCESS") {
      return {
        hash,
        ledger: status.ledger ?? status.latestLedger,
        returnValue: status.returnValue,
        events: status.events,
      };
    }
    if (status.status === "FAILED") {
      throw new CyphrasError("transaction_failed", "the transaction failed on chain", { hash });
    }
    if (Date.now() > deadline) {
      throw new CyphrasError("transaction_failed", "the transaction expired unconfirmed", { hash });
    }
    await ctx.sleep(POLL_MS);
  }
}
