import { Address, nativeToScVal, scValToBigInt, xdr } from "@stellar/stellar-base";
import { hexToBytes } from "../bytes.ts";
import { CyphrasError, fail } from "../errors.ts";
import { extDataToScVal, isAccountId, txProofToScVal } from "../extdata.ts";
import { EMPTY_ROOT } from "../merkle.ts";
import type { DepositQueue } from "../net/indexer.ts";
import { proveTransaction } from "../proving.ts";
import { buildTransaction } from "../transaction.ts";
import { type TransactionSigner, invokeVault } from "../vault/invoke.ts";
import type { VaultInstance } from "../vault/state.ts";
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

/** A submitted deposit: its ID in the entry queue and its transaction. */
export interface ShieldReceipt {
  readonly depositId: number;
  readonly txHash: string;
}

// Proves a deposit with two dummy inputs and both outputs to the wallet's own address, has the
// depositor sign it, and submits it through the RPC.
export async function shield(
  core: Core,
  amount: bigint,
  signer: TransactionSigner,
): Promise<ShieldReceipt> {
  const keys = spendingKeys(core);
  if (core.prover === undefined || core.artifacts === undefined) {
    fail("invalid_argument", "this wallet was opened without a prover and artifacts");
  }
  if (!isAccountId(signer.publicKey)) fail("invalid_argument", "the depositor must be a G account");
  if (amount <= 0n) fail("invalid_argument", "the amount must be positive");
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
      async (hash) => {
        deposit.txHash = hash;
        await core.save();
      },
    );
    if (result.returnValue?.switch().name !== "scvU64") {
      fail("rpc_error", "the shield returned no deposit ID");
    }
    deposit.id = Number(scValToBigInt(result.returnValue));
    deposit.state = "pending";
    await core.save();
    return { depositId: deposit.id, txHash: result.hash };
  } catch (err) {
    // A deposit that never reached the network is void; one that did is settled by the next sync.
    if (deposit.txHash === undefined && err instanceof CyphrasError) {
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
  const result = await invokeVault(invokeContext(core), signer, {
    fn: "cancel",
    args: [u64(id)],
    transfers: [],
  });
  const record = core.state.deposits.find((d) => d.id === id);
  if (record !== undefined) {
    record.state = "cancelled";
    record.refundReason = 0;
    await core.save();
  }
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
  const result = await invokeVault(invokeContext(core), signer, {
    fn: "refund",
    args: [u64(id)],
    transfers: [],
  });
  const record = core.state.deposits.find((d) => d.id === id);
  if (record !== undefined) {
    record.state = "refunded";
    record.refundReason = pending.flag;
    await core.save();
  }
  return result.hash;
}

// The ID of the deposit a transaction made, or its failure, as every RPC provider reports it; none
// while they differ, cannot answer or do not hold the transaction yet.
async function depositOutcome(core: Core, hash: string): Promise<number | "failed" | undefined> {
  const { rpc, second } = core.services;
  const outcomes: (number | "failed" | undefined)[] = [];
  for (const provider of second === undefined ? [rpc] : [rpc, second.rpc]) {
    const status = await provider.getTransaction(hash).catch((err: unknown) => {
      if (err instanceof CyphrasError) return undefined;
      throw err;
    });
    outcomes.push(
      status?.status === "FAILED"
        ? "failed"
        : status?.status === "SUCCESS" && status.returnValue?.switch().name === "scvU64"
          ? Number(scValToBigInt(status.returnValue))
          : undefined,
    );
  }
  return outcomes.every((o) => o === outcomes[0]) ? outcomes[0] : undefined;
}

// Follows this wallet's deposits through the entry queue. A deposit still being submitted is found
// by its commitments in the vault's deposit_pending events, of ledgers every RPC provider showed
// alike, even when this wallet never learned its transaction, or by its transaction as every
// provider reports it; one that cannot land any more, with every ledger up to its deadline
// checked, failed. A deposit's notes are spendable only once admitted, which is when their leaves
// appear.
export async function trackDeposits(
  core: Core,
  queue: DepositQueue | undefined,
  events: readonly DepositEvent[],
): Promise<void> {
  const state: WalletState = core.state;
  for (const deposit of state.deposits) {
    if (deposit.state === "submitting") {
      const pending = events.find(
        (e) =>
          e.commitments[0] === deposit.commitments[0] &&
          e.commitments[1] === deposit.commitments[1],
      );
      if (pending !== undefined) {
        deposit.id = pending.id;
        deposit.txHash = pending.txHash;
        deposit.state = "pending";
      } else if (deposit.txHash !== undefined) {
        const outcome = await depositOutcome(core, deposit.txHash);
        if (outcome === "failed") {
          deposit.state = "failed";
        } else if (outcome !== undefined) {
          deposit.id = outcome;
          deposit.state = "pending";
        }
      }
      if (
        deposit.state === "submitting" &&
        checkedBetween(state, deposit.builtAt, deposit.deadline)
      ) {
        deposit.state = "failed";
      }
    }
    if (deposit.state !== "pending" || deposit.id === undefined) continue;
    if (state.notes.some((n) => deposit.commitments.includes(n.cm))) {
      deposit.state = "admitted";
      deposit.flag = undefined;
      continue;
    }
    const queued = queue?.pending.find((d) => d.id === deposit.id);
    const resolved = queue?.resolved.find((d) => d.id === deposit.id);
    if (queued !== undefined) {
      deposit.attested = queued.attested;
      deposit.earliestAdmission = queued.earliestAdmission;
      deposit.flag = queued.flag;
    } else if (resolved !== undefined) {
      deposit.state = resolved.outcome;
      deposit.leafIndices = resolved.leafIndices;
      deposit.refundReason = resolved.reason;
      deposit.flag = undefined;
    }
  }
}
