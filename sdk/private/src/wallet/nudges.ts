import { MuxedAccount } from "@stellar/stellar-base";
import { isMuxedAccountId } from "../extdata.ts";
import type { Deposit, OwnedNote } from "./state.ts";

/** A reason to pause before an unshield, which the user confirms or the SDK refuses. */
export type WarningCode =
  | "destination_shielded_from_wallet"
  | "amount_matches_shield"
  | "recent_shield"
  | "whole_balance_after_shield"
  | "new_destination_account"
  | "destination_created_by_payout"
  | "small_anonymity_set"
  | "anonymity_set_unknown"
  | "self_relay_links_account"
  | "exit_will_queue";

/** A warning with a fixed, user-facing explanation. */
export interface Warning {
  readonly code: WarningCode;
  readonly message: string;
}

const MESSAGES: Readonly<Record<WarningCode, string>> = {
  destination_shielded_from_wallet:
    "This account has deposited into this wallet, so the unshield links back to it.",
  amount_matches_shield:
    "The amount equals a recent deposit of this wallet; matching amounts link a deposit to its withdrawal.",
  recent_shield:
    "This wallet deposited less than 24 hours ago; a quick withdrawal is easy to link to the deposit.",
  whole_balance_after_shield:
    "This withdraws the whole balance right after a deposit, which links the two.",
  new_destination_account:
    "The destination account is new; whoever funded it can be linked to this withdrawal.",
  destination_created_by_payout:
    "The destination account does not exist yet: this withdrawal creates it, so the pool alone funds it and nothing else links it to you. 1 XLM of it stays locked as the account's minimum balance, so send more than the recipient needs to spend.",
  small_anonymity_set:
    "Few deposits have entered the pool, so this withdrawal hides among only a few others.",
  anonymity_set_unknown: "The size of the pool's anonymity set could not be read.",
  self_relay_links_account:
    "Without a relayer, your Stellar account submits the withdrawal and is publicly linked to it.",
  exit_will_queue:
    "The vault's daily outflow is used up or its exit queue is not empty, so this payout waits in the queue.",
};

export const warning = (code: WarningCode): Warning => ({ code, message: MESSAGES[code] });

// The SDK's defaults for when an unshield warns.
const NUDGE_THRESHOLDS = {
  recentShieldMs: 24 * 3_600_000,
  matchingWindowMs: 30 * 24 * 3_600_000,
  // About 30 days of five-second ledgers.
  newAccountLedgers: 518_400,
  minAnonymitySet: 100,
} as const;

export interface UnshieldContext {
  readonly to: string;
  readonly amount: bigint;
  readonly fee: bigint;
  readonly spendable: bigint;
  readonly deposits: readonly Deposit[];
  readonly notes: readonly OwnedNote[];
  readonly now: number;
  readonly destinationCreatedLedger: number | undefined;
  readonly createsAccount: boolean;
  readonly latestLedger: number;
  readonly admittedDeposits: number | undefined;
  readonly selfRelay: boolean;
  readonly willQueue: boolean;
}

const baseAccount = (address: string): string =>
  isMuxedAccountId(address)
    ? MuxedAccount.fromAddress(address, "0").baseAccount().accountId()
    : address;

// The warnings an unshield shows for review: what could link it to the wallet or its deposits,
// a small anonymity set, and a payout that will wait in the exit queue.
export function unshieldWarnings(c: UnshieldContext): Warning[] {
  const codes: WarningCode[] = [];
  const shields = c.deposits.filter((d) => d.state !== "failed");
  if (shields.some((d) => d.depositor === baseAccount(c.to))) {
    codes.push("destination_shielded_from_wallet");
  }
  const recent = shields.filter((d) => c.now - d.createdAt < NUDGE_THRESHOLDS.matchingWindowMs);
  const fromShields = new Set(recent.flatMap((d) => d.commitments));
  const shieldValues = [
    ...recent.map((d) => d.amount),
    ...c.notes.filter((n) => fromShields.has(n.cm)).map((n) => n.value),
  ];
  if (shieldValues.some((v) => v === c.amount || v === c.amount + c.fee)) {
    codes.push("amount_matches_shield");
  }
  const lastShield = Math.max(0, ...shields.map((d) => d.createdAt));
  const shieldedLately = c.now - lastShield < NUDGE_THRESHOLDS.recentShieldMs;
  if (shieldedLately) codes.push("recent_shield");
  if (shieldedLately && c.amount + c.fee >= c.spendable) codes.push("whole_balance_after_shield");
  if (c.createsAccount) {
    codes.push("destination_created_by_payout");
  } else if (
    c.destinationCreatedLedger !== undefined &&
    c.latestLedger - c.destinationCreatedLedger < NUDGE_THRESHOLDS.newAccountLedgers
  ) {
    codes.push("new_destination_account");
  }
  if (c.admittedDeposits === undefined) codes.push("anonymity_set_unknown");
  else if (c.admittedDeposits < NUDGE_THRESHOLDS.minAnonymitySet) codes.push("small_anonymity_set");
  if (c.selfRelay) codes.push("self_relay_links_account");
  if (c.willQueue) codes.push("exit_will_queue");
  return codes.map(warning);
}
