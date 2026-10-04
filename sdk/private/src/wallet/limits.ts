import { fail } from "../errors.ts";
import { isAccountId } from "../extdata.ts";
import type { Core } from "./core.ts";

/** The vault's limits as one read of the chain shows them, with what is left of them now. */
export interface VaultLimitsView {
  // The ledger the vault was read at.
  readonly ledger: number;
  readonly minDeposit: bigint;
  readonly maxDeposit: bigint;
  // What the vault takes before its TVL cap.
  readonly tvlRoom: bigint;
  // What one depositor may deposit in a UTC day, and, for the depositor asked about, what is left
  // of it today.
  readonly maxDailyPerDepositor: bigint;
  readonly depositorRoomToday: bigint | undefined;
  // The largest deposit the vault takes now: within its maximum, its TVL room and, for the
  // depositor asked about, what is left of its day.
  readonly depositRoom: bigint;
  // A deposit of at least largeDepositThreshold waits delayLarge seconds before it can be
  // admitted, a smaller one delaySmall.
  readonly largeDepositThreshold: bigint;
  readonly delaySmall: number;
  readonly delayLarge: number;
  // The most one exit pays out with its fee, and what today's outflow window has left before a
  // payout waits in the exit queue; any payout waits while exits are queued.
  readonly maxDailyOutflow: bigint;
  readonly outflowLeftToday: bigint;
  readonly queuedExits: number;
  // The largest relayer fee the vault takes.
  readonly maxFee: bigint;
  readonly depositsPaused: boolean;
  readonly transfersPaused: boolean;
  // Unix seconds until which the vault is halted, while it is.
  readonly haltedUntil: number | undefined;
}

const least = (...xs: bigint[]): bigint => xs.reduce((a, b) => (a < b ? a : b));
const atLeastZero = (x: bigint): bigint => (x > 0n ? x : 0n);

// The vault's limits from one RPC read of its instance, with days counted as the vault counts
// them, in UTC, by the wallet's clock.
export async function vaultLimits(
  core: Core,
  depositor: string | undefined,
): Promise<VaultLimitsView> {
  if (depositor !== undefined && !isAccountId(depositor)) {
    fail("invalid_argument", "the depositor must be a G account");
  }
  const { vault } = core.services;
  const { config, limits, status, latestLedger } = await vault.instance();
  const now = BigInt(Math.floor(core.now() / 1000));
  const day = now / 86_400n;
  const tvlRoom = atLeastZero(limits.tvlCap - status.tvl);
  const depositorRoomToday =
    depositor === undefined
      ? undefined
      : atLeastZero(limits.maxDailyPerDepositor - (await vault.depositorDayTotal(depositor, day)));
  const usedToday = status.outflowDay === day ? status.outflow : 0n;
  return {
    ledger: latestLedger,
    minDeposit: limits.minDeposit,
    maxDeposit: limits.maxDeposit,
    tvlRoom,
    maxDailyPerDepositor: limits.maxDailyPerDepositor,
    depositorRoomToday,
    depositRoom: least(limits.maxDeposit, tvlRoom, depositorRoomToday ?? tvlRoom),
    largeDepositThreshold: limits.largeDepositThreshold,
    delaySmall: Number(config.delaySmall),
    delayLarge: Number(config.delayLarge),
    maxDailyOutflow: limits.maxDailyOutflow,
    outflowLeftToday: atLeastZero(limits.maxDailyOutflow - usedToday),
    queuedExits: Number(status.exitTail - status.exitHead),
    maxFee: limits.maxFee,
    depositsPaused: status.depositsPaused,
    transfersPaused: status.transfersPaused,
    haltedUntil: now < status.haltedUntil ? Number(status.haltedUntil) : undefined,
  };
}
