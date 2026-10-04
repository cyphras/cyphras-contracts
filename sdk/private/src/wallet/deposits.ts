import { Address, nativeToScVal, scValToBigInt, xdr } from "@stellar/stellar-base";
import { hexToBytes } from "../bytes.ts";
import { CyphrasError, fail } from "../errors.ts";
import { extDataToScVal, isAccountId, txProofToScVal } from "../extdata.ts";
import { EMPTY_ROOT } from "../merkle.ts";
import type { DepositQueue } from "../net/indexer.ts";
import type { SorobanRpc, TransactionStatus } from "../net/rpc.ts";
import { proveTransaction } from "../proving.ts";
import { buildTransaction } from "../transaction.ts";
import { type TransactionSigner, askTransaction, invokeVault } from "../vault/invoke.ts";
import type { PendingDepositEntry, VaultInstance } from "../vault/state.ts";
import { type Core, invokeContext, spendingKeys } from "./core.ts";
import { DEADLINE_LEDGERS } from "./spend.ts";
import type { DepositEvent } from "./sources.ts";
import { checkedBetween } from "./sync.ts";
import type { Deposit, WalletState } from "./state.ts";

/**
 * What the screening's reason code on a deposit means. "held_for_review" (6) is no refusal: a
 * review may still clear the deposit, which is then admitted, and one still held a day after the
 * hold is refunded. "refused_by_reviewer" (5) is a reviewer's refusal. "legal_hold" (100) holds the
 * deposit under a written order from an authority: no service refunds it, though its depositor can
 * still take it back. "refused" is a refusal of the screening policy: a sanctioned address (1), an
 * exploit (2), frozen funds (3), a fraud report (4) or another reason a person gave (99).
 * "cancelled" (0) is the depositor's own taking back. "unknown" is a code this release does not
 * know, which says nothing of whether the deposit may still be admitted.
 */
export type ScreeningKind =
  | "held_for_review"
  | "refused_by_reviewer"
  | "legal_hold"
  | "refused"
  | "cancelled"
  | "unknown";

function screeningKind(reason: number): ScreeningKind {
  switch (reason) {
    case 0:
      return "cancelled";
    case 1:
    case 2:
    case 3:
    case 4:
    case 99:
      return "refused";
    case 5:
      return "refused_by_reviewer";
    case 6:
      return "held_for_review";
    case 100:
      return "legal_hold";
    default:
      return "unknown";
  }
}

/** A deposit made by this wallet, as it moves through the vault's entry queue. */
export interface DepositInfo {
  readonly id: number | undefined;
  readonly amount: bigint;
  readonly depositor: string;
  readonly state: Deposit["state"];
  readonly txHash: string | undefined;
  readonly attested: boolean | undefined;
  // Unix seconds.
  readonly earliestAdmission: number | undefined;
  readonly flag:
    | {
        readonly reason: number;
        readonly kind: ScreeningKind;
        readonly flaggedAt: number | undefined;
      }
    | undefined;
  // Unix seconds from which anyone may claim the refund of a flagged deposit, and from which a
  // deposit still held for review is refunded.
  readonly refundableAt: number | undefined;
  readonly refundReason: number | undefined;
  readonly refundKind: ScreeningKind | undefined;
  // The state and the entry queue's details rest on every RPC provider's reads of the entry queue,
  // the wallet's own transactions every provider reports, the vault's events every provider showed
  // and the confirmed tree, rather than on the indexer's account alone.
  readonly confirmed: boolean;
}

// Anyone may refund a flagged deposit only a day after it was flagged; the depositor can cancel
// at any time.
const REFUND_DELAY_SECONDS = 86_400;

export function depositInfo(d: Deposit): DepositInfo {
  return {
    id: d.id,
    amount: d.amount,
    depositor: d.depositor,
    state: d.state,
    txHash: d.txHash,
    attested: d.attested,
    earliestAdmission: d.earliestAdmission,
    flag: d.flag === undefined ? undefined : { ...d.flag, kind: screeningKind(d.flag.reason) },
    refundableAt:
      d.flag?.flaggedAt === undefined ? undefined : d.flag.flaggedAt + REFUND_DELAY_SECONDS,
    refundReason: d.refundReason,
    refundKind: d.refundReason === undefined ? undefined : screeningKind(d.refundReason),
    confirmed: d.confirmed,
  };
}

const u64 = (n: number | bigint): xdr.ScVal => xdr.ScVal.scvU64(new xdr.Uint64(BigInt(n)));

async function checkDepositLimits(
  core: Core,
  instance: VaultInstance,
  depositor: string,
  amount: bigint,
): Promise<void> {
  const { limits, status } = instance;
  const now = BigInt(Math.floor(core.now() / 1000));
  if (now < status.haltedUntil) fail("vault_unavailable", "the vault is halted");
  if (status.depositsPaused) fail("vault_unavailable", "deposits are paused");
  if (amount < limits.minDeposit) {
    fail("limit_exceeded", "the amount is below the vault's minimum deposit", {
      minDeposit: limits.minDeposit.toString(),
    });
  }
  if (amount > limits.maxDeposit) {
    fail("limit_exceeded", "the amount is above the vault's maximum deposit", {
      maxDeposit: limits.maxDeposit.toString(),
    });
  }
  if (status.tvl + amount > limits.tvlCap) {
    fail("limit_exceeded", "the deposit would take the vault over its TVL cap", {
      room: (limits.tvlCap - status.tvl).toString(),
    });
  }
  const today = await core.services.vault.depositorDayTotal(depositor, now / 86_400n);
  if (today + amount > limits.maxDailyPerDepositor) {
    fail("limit_exceeded", "the deposit exceeds this account's daily limit", {
      room: (limits.maxDailyPerDepositor - today).toString(),
    });
  }
}

/**
 * A submitted deposit: its ID in the entry queue and its transaction. The ID is undefined while the
 * RPC providers do not all report the transaction alike within half a minute; a later sync takes
 * it from the chain.
 */
export interface ShieldReceipt {
  readonly depositId: number | undefined;
  readonly txHash: string;
}

// Proves a deposit with two dummy inputs and both outputs to the wallet's own address, has the
// depositor sign it, and submits it through the RPC. While another deposit of this wallet is still
// being submitted, and so may yet land, it goes only `whileSubmitting`.
export async function shield(
  core: Core,
  amount: bigint,
  signer: TransactionSigner,
  whileSubmitting: boolean,
): Promise<ShieldReceipt> {
  const keys = spendingKeys(core);
  if (core.prover === undefined || core.artifacts === undefined) {
    fail("invalid_argument", "this wallet was opened without a prover and artifacts");
  }
  if (!isAccountId(signer.publicKey)) fail("invalid_argument", "the depositor must be a G account");
  if (amount <= 0n) fail("invalid_argument", "the amount must be positive");
  if (!whileSubmitting && core.state.deposits.some((d) => d.state === "submitting")) {
    fail(
      "deposit_submitting",
      "another deposit of this wallet is still being submitted, and may yet land",
    );
  }
  const instance = await core.services.vault.instance();
  await checkDepositLimits(core, instance, signer.publicKey, amount);

  const latest = await core.services.rpc.getLatestLedger();
  const deadline = latest + DEADLINE_LEDGERS;
  const built = buildTransaction({
    keys,
    self: core.self,
    root: EMPTY_ROOT,
    domain: core.deployment.domain,
    inputs: [],
    outputs: [
      { address: core.self, value: amount },
      { address: core.self, value: 0n },
    ],
    ext: {
      vault: core.deployment.vault,
      networkId: hexToBytes(core.services.networkId),
      deadline,
      extAmount: amount,
      fee: 0n,
      recipient: signer.publicKey,
      relayer: signer.publicKey,
    },
  });
  const proof = await proveTransaction(built.witness, core.prover, core.artifacts);
  const deposit: Deposit = {
    id: undefined,
    depositor: signer.publicKey,
    amount,
    commitments: built.commitments,
    createdAt: core.now(),
    builtAt: latest,
    deadline,
    txHash: undefined,
    state: "submitting",
    attested: undefined,
    earliestAdmission: undefined,
    flag: undefined,
    leafIndices: undefined,
    refundReason: undefined,
    confirmed: true,
    seenAt: undefined,
    goneAt: undefined,
    ownReturn: undefined,
  };
  core.state.deposits.push(deposit);
  await core.save();

  const vault = new Address(core.deployment.vault).toScVal();
  const depositor = new Address(signer.publicKey).toScVal();
  try {
    const result = await invokeVault(
      invokeContext(core),
      signer,
      {
        fn: "shield",
        args: [txProofToScVal(proof), extDataToScVal(built.ext), depositor],
        transfers: [
          {
            token: core.deployment.asset.contract,
            args: [depositor, vault, nativeToScVal(amount, { type: "i128" })],
          },
        ],
      },
      {
        onSending: async (hash) => {
          deposit.txHash = hash;
          await core.save();
        },
      },
    );
    // The deposit's ID counts once every RPC provider reports its transaction alike; until then the
    // deposit stays submitting, and a sync takes its ID from the chain.
    const outcome = outcomeOf(
      await askTransaction(invokeContext(core), providers(core), result.hash),
      deposit,
    );
    if (typeof outcome === "number") {
      deposit.id = outcome;
      deposit.state = "pending";
    }
    await core.save();
    return { depositId: deposit.id, txHash: result.hash };
  } catch (err) {
    // A deposit whose envelope never left the device is void. One that may have reached the
    // network stays submitting with its hash, whatever the RPC it went through answered, for a
    // sync to settle.
    if (err instanceof CyphrasError && deposit.txHash === undefined) {
      deposit.state = "failed";
      await core.save();
    }
    throw err;
  }
}

export async function cancelDeposit(
  core: Core,
  id: number,
  signer: TransactionSigner,
): Promise<string> {
  const pending = await core.services.vault.pending(BigInt(id));
  if (pending === undefined) fail("not_found", "no pending deposit has that ID");
  if (pending.depositor !== signer.publicKey) {
    fail("invalid_argument", "only the depositor can cancel a deposit");
  }
  await claimId(core, id);
  const result = await invokeVault(invokeContext(core), signer, {
    fn: "cancel",
    args: [u64(id)],
    transfers: [],
  });
  await returned(core, id, "cancelled", 0, result.hash);
  return result.hash;
}

export async function refundDeposit(
  core: Core,
  id: number,
  signer: TransactionSigner,
): Promise<string> {
  const pending = await core.services.vault.pending(BigInt(id));
  if (pending === undefined) fail("not_found", "no pending deposit has that ID");
  if (pending.flag === undefined) fail("invalid_argument", "the deposit is not flagged");
  const now = BigInt(Math.floor(core.now() / 1000));
  if (now < pending.flaggedAt + BigInt(REFUND_DELAY_SECONDS)) {
    fail(
      "vault_unavailable",
      "a flagged deposit can be refunded a day after the flag; its depositor can cancel now",
      {
        refundableAt: (pending.flaggedAt + BigInt(REFUND_DELAY_SECONDS)).toString(),
      },
    );
  }
  await claimId(core, id);
  const result = await invokeVault(invokeContext(core), signer, {
    fn: "refund",
    args: [u64(id)],
    transfers: [],
  });
  await returned(core, id, "refunded", pending.flag, result.hash);
  return result.hash;
}

// Records this wallet's cancel or refund of a deposit, which counts once every RPC provider reports
// its transaction a success; until then the deposit is followed on the chain.
async function returned(
  core: Core,
  id: number,
  how: "cancelled" | "refunded",
  reason: number | undefined,
  hash: string,
): Promise<void> {
  const record = core.state.deposits.find((d) => d.id === id);
  if (record === undefined) return;
  const statuses = await askTransaction(invokeContext(core), providers(core), hash);
  record.state = how;
  record.refundReason = reason;
  record.ownReturn = how;
  record.confirmed = statuses.every((s) => s?.status === "SUCCESS");
  await core.save();
}

const providers = (core: Core): SorobanRpc[] =>
  core.services.second === undefined
    ? [core.services.rpc]
    : [core.services.rpc, core.services.second.rpc];

// What every RPC provider reports of a deposit's shield transaction: the ID it made, once they all
// report it alike; failed, once every one reports it failed, or missing while it holds every
// ledger the deposit could have been made in, at a ledger past its proof's deadline, after which
// it can no longer land; none otherwise.
function outcomeOf(
  statuses: readonly (TransactionStatus | undefined)[],
  deposit: Deposit,
): number | "failed" | undefined {
  const ended = (s: TransactionStatus | undefined): boolean =>
    s !== undefined &&
    s.latestLedger > deposit.deadline &&
    (s.status === "FAILED" ||
      (s.status === "NOT_FOUND" && (s.oldestLedger ?? Infinity) <= deposit.builtAt + 1));
  if (statuses.every(ended)) return "failed";
  const ids = statuses.map(idOf);
  return ids.every((id) => id === ids[0]) ? ids[0] : undefined;
}

// The ID of the deposit a shield transaction made, as one provider reports it.
const idOf = (s: TransactionStatus | undefined): number | undefined =>
  s?.status === "SUCCESS" && s.returnValue?.switch().name === "scvU64"
    ? Number(scValToBigInt(s.returnValue))
    : undefined;

// Every RPC provider's report of a transaction, none where one cannot answer.
async function statusesOf(core: Core, hash: string): Promise<(TransactionStatus | undefined)[]> {
  const statuses: (TransactionStatus | undefined)[] = [];
  for (const provider of providers(core)) {
    statuses.push(
      await provider.getTransaction(hash).catch((err: unknown) => {
        if (err instanceof CyphrasError) return undefined;
        throw err;
      }),
    );
  }
  return statuses;
}

// What each RPC provider shows of the entry queue under an ID: its entry, or none, and the ledger
// it read at.
type QueueRead = readonly {
  readonly entry: PendingDepositEntry | undefined;
  readonly ledger: number;
}[];

// Every RPC provider's reads of the entry queue under these IDs, in one read from each; nothing
// while a provider cannot answer.
async function readQueue(core: Core, ids: readonly number[]): Promise<Map<number, QueueRead>> {
  const out = new Map<number, QueueRead>();
  if (ids.length === 0) return out;
  const { vault, second } = core.services;
  const reads: Awaited<ReturnType<typeof vault.pendings>>[] = [];
  for (const reader of second === undefined ? [vault] : [vault, second.vault]) {
    const read = await reader.pendings(ids.map(BigInt)).catch((err: unknown) => {
      if (err instanceof CyphrasError) return undefined;
      throw err;
    });
    if (read === undefined) return out;
    reads.push(read);
  }
  for (const id of ids) {
    out.set(
      id,
      reads.map((r) => ({ entry: r.entries.get(BigInt(id)), ledger: r.ledger })),
    );
  }
  return out;
}

const entryKey = (e: PendingDepositEntry | undefined): string =>
  JSON.stringify(e, (_k, v: unknown) => (typeof v === "bigint" ? `${v}` : v)) ?? "";

// The entry every provider shows alike under an ID, if they all show one.
function alike(read: QueueRead | undefined): PendingDepositEntry | undefined {
  const [first, ...rest] = read ?? [];
  const entry = first?.entry;
  return entry !== undefined && rest.every((r) => entryKey(r.entry) === entryKey(entry))
    ? entry
    : undefined;
}

// The deposit as the entry queue holds it: pending, with the chain's flag, the time from which it
// can be admitted and whether it is attested.
function follow(deposit: Deposit, entry: PendingDepositEntry, attestedUpTo: bigint): void {
  deposit.state = "pending";
  deposit.flag =
    entry.flag === undefined
      ? undefined
      : { reason: entry.flag, flaggedAt: Number(entry.flaggedAt) };
  deposit.earliestAdmission = Number(entry.createdAt + entry.delay);
  deposit.attested = BigInt(deposit.id as number) <= attestedUpTo;
  deposit.refundReason = undefined;
  deposit.goneAt = undefined;
  deposit.confirmed = true;
}

// Records the newest ledger at which a provider showed the deposit in the entry queue.
function see(deposit: Deposit, read: QueueRead | undefined): void {
  for (const r of read ?? []) {
    if (r.entry !== undefined) deposit.seenAt = Math.max(deposit.seenAt ?? 0, r.ledger);
  }
}

// Whether the entry queue's entry is this deposit's: its depositor's, of its amount, holding its
// commitments.
const holds = (entry: PendingDepositEntry | undefined, deposit: Deposit): boolean =>
  entry !== undefined &&
  entry.depositor === deposit.depositor &&
  entry.amount === deposit.amount &&
  entry.commitments[0] === deposit.commitments[0] &&
  entry.commitments[1] === deposit.commitments[1];

// A deposit of this wallet still being submitted takes the ID a cancel or a refund names, once
// every RPC provider's entry under it holds the deposit.
async function claimId(core: Core, id: number): Promise<void> {
  if (core.state.deposits.some((d) => d.id === id)) return;
  const entry = alike((await readQueue(core, [id])).get(id));
  const deposit = core.state.deposits.find(
    (d) => d.state === "submitting" && d.id === undefined && holds(entry, d),
  );
  if (deposit === undefined) return;
  deposit.id = id;
  deposit.state = "pending";
  await core.save();
}

// What a sync's reads of the vault show beyond the deposits' entries: the ledger up to which the
// confirmed tree holds every leaf, and the last deposit every RPC provider shows attested.
export interface QueueContext {
  readonly treeAt: number;
  readonly attestedUpTo: bigint;
}

// Follows this wallet's deposits through the entry queue. A deposit still being submitted is found
// by its commitments in the vault's deposit_pending events, of ledgers every RPC provider showed
// alike, even when this wallet never learned its transaction; by its transaction as every
// provider reports it; or under an ID that any provider's events or report of its transaction,
// or the indexer's entries for its depositor and amount, give, once every provider's entry under
// that ID holds its commitments. One that cannot land any more, as every provider reports its
// transaction or every ledger up to its deadline checked shows, failed, until checked events or
// the entry queue show it made after all. Until every source confirms what became of it, a
// deposit is followed in the entry queue as every provider shows it, where an entry still there
// outweighs any resolution the indexer gave. One gone from the queue whose notes are not in the
// confirmed tree of a later ledger went back to its depositor. A deposit's notes are spendable
// only once admitted, which is when their leaves appear.
export async function trackDeposits(
  core: Core,
  queue: DepositQueue | undefined,
  events: readonly DepositEvent[],
  heard: readonly DepositEvent[],
  context: QueueContext,
): Promise<void> {
  const state: WalletState = core.state;
  const holding = (e: DepositEvent, d: Deposit): boolean =>
    e.commitments[0] === d.commitments[0] && e.commitments[1] === d.commitments[1];
  // A resolution every source confirmed is final.
  const followed = (d: Deposit): boolean =>
    d.id !== undefined &&
    d.state !== "submitting" &&
    d.state !== "failed" &&
    (d.state === "pending" || !d.confirmed);
  const unnamed = state.deposits.filter(
    (d) => (d.state === "submitting" || d.state === "failed") && d.id === undefined,
  );
  // Every provider's report of the transaction of each deposit still being submitted that no
  // checked event shows.
  const reports = new Map<Deposit, (TransactionStatus | undefined)[]>();
  for (const d of unnamed) {
    if (d.state === "submitting" && d.txHash !== undefined && !events.some((e) => holding(e, d))) {
      reports.set(d, await statusesOf(core, d.txHash));
    }
  }
  // The IDs a deposit without one may have.
  const candidates = (d: Deposit): number[] => [
    ...new Set([
      ...heard.filter((e) => holding(e, d)).map((e) => e.id),
      ...(reports.get(d) ?? []).flatMap((s) => idOf(s) ?? []),
      ...(queue?.pending ?? [])
        .filter((e) => e.depositor === d.depositor && e.amount === d.amount)
        .map((e) => e.id),
    ]),
  ];
  const reads = await readQueue(core, [
    ...new Set([
      ...unnamed.flatMap(candidates),
      ...state.deposits.filter(followed).map((d) => d.id as number),
    ]),
  ]);
  for (const deposit of state.deposits) {
    // The confirmed tree outweighs whatever else said what became of the deposit.
    if (state.notes.some((n) => deposit.commitments.includes(n.cm))) {
      deposit.state = "admitted";
      deposit.flag = undefined;
      deposit.goneAt = undefined;
      deposit.confirmed = true;
      continue;
    }
    const made = events.find((e) => holding(e, deposit));
    // A deposit taken for failed that the vault's events show made after all is being submitted.
    if (deposit.state === "failed" && made !== undefined) deposit.state = "submitting";
    if (deposit.state === "submitting") {
      const reported = reports.get(deposit);
      const outcome = reported === undefined ? undefined : outcomeOf(reported, deposit);
      if (made !== undefined) {
        deposit.id = made.id;
        deposit.txHash = made.txHash;
        deposit.state = "pending";
      } else if (outcome === "failed") {
        deposit.state = "failed";
      } else if (outcome !== undefined) {
        deposit.id = outcome;
        deposit.state = "pending";
      }
    }
    if (
      (deposit.state === "submitting" || deposit.state === "failed") &&
      deposit.id === undefined
    ) {
      const found = candidates(deposit).find((id) => holds(alike(reads.get(id)), deposit));
      if (found !== undefined) {
        deposit.id = found;
        see(deposit, reads.get(found));
        follow(deposit, alike(reads.get(found)) as PendingDepositEntry, context.attestedUpTo);
        continue;
      }
    }
    if (
      deposit.state === "submitting" &&
      checkedBetween(state, deposit.builtAt, deposit.deadline)
    ) {
      deposit.state = "failed";
    }
    if (!followed(deposit)) continue;
    const read = reads.get(deposit.id as number);
    see(deposit, read);
    const entry = alike(read);
    if (holds(entry, deposit)) {
      follow(deposit, entry as PendingDepositEntry, context.attestedUpTo);
      continue;
    }
    // Gone from the entry queue only on every provider's read of a ledger past the last one any
    // provider showed the deposit at, and past its proof's deadline, by which it was made; a
    // provider that shows it again undoes that. Gone, it is no longer as the chain last showed it.
    const gone =
      read !== undefined &&
      read.every((r) => r.entry === undefined) &&
      Math.min(...read.map((r) => r.ledger)) > Math.max(deposit.deadline, deposit.seenAt ?? 0);
    if (gone) {
      deposit.goneAt ??= Math.max(...read.map((r) => r.ledger));
      deposit.confirmed = false;
    } else if (read?.some((r) => r.entry !== undefined)) {
      deposit.goneAt = undefined;
    }
    const { goneAt } = deposit;
    if (gone && goneAt !== undefined && context.treeAt >= goneAt) {
      const cancelled = deposit.ownReturn === "cancelled";
      deposit.state = cancelled ? "cancelled" : "refunded";
      deposit.refundReason = cancelled ? 0 : (deposit.refundReason ?? deposit.flag?.reason);
      deposit.flag = undefined;
      deposit.confirmed = true;
      continue;
    }
    // While the chain says no more, the indexer's account, which counts only for the depositor and
    // amount of this deposit, so that no other deposit's state shows under its ID.
    const ours = (d: { id: number; depositor: string; amount: bigint }): boolean =>
      d.id === deposit.id && d.depositor === deposit.depositor && d.amount === deposit.amount;
    const queued = queue?.pending.find(ours);
    const resolved = queue?.resolved.find(ours);
    if (queued !== undefined) {
      deposit.state = "pending";
      deposit.attested = queued.attested;
      deposit.earliestAdmission = queued.earliestAdmission;
      deposit.flag = queued.flag;
      deposit.refundReason = undefined;
      deposit.confirmed = false;
    } else if (resolved !== undefined) {
      deposit.state = resolved.outcome;
      deposit.leafIndices = resolved.leafIndices;
      deposit.refundReason = resolved.reason;
      deposit.flag = undefined;
      deposit.confirmed = false;
    }
  }
}
