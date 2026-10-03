import type { LedgerTime, WalletState } from "./state.ts";

// The pace the network aims at, taken when no close times give one, and the most a wallet takes:
// a slower pace would shorten held deadlines that a relayer's own estimate may not allow.
const FALLBACK_SECONDS = 5;
// The least a wallet takes: close times that lie can at most double the ledgers a held proof stays
// valid for, beyond what the fallback gives.
const MIN_SECONDS = FALLBACK_SECONDS / 2;
// A pace is taken only over a span of at least this many ledgers, as the relayers take theirs.
const MIN_SPAN = 60;
// How far back the close times kept between syncs reach.
const KEPT_SECONDS = 3_600;

// The seconds per ledger up to the newest close time: the fastest from any time at least 60
// ledgers before it.
function paceOf(times: readonly LedgerTime[], newest: LedgerTime): number {
  let pace = FALLBACK_SECONDS;
  for (const t of times) {
    const span = newest.ledger - t.ledger;
    if (span >= MIN_SPAN) pace = Math.min(pace, (newest.at - t.at) / span);
  }
  return Math.max(pace, MIN_SECONDS);
}

// Takes the close times RPC reported in this sync with those kept from the last hour's syncs, and
// returns the pace of ledgers they give. Kept times are spaced by the span a pace needs.
export function updatePace(state: WalletState, reported: readonly LedgerTime[]): number {
  const times = [...state.ledgerTimes, ...reported].sort((a, b) => a.ledger - b.ledger);
  const newest = times[times.length - 1];
  if (newest === undefined) return FALLBACK_SECONDS;
  const kept: LedgerTime[] = [];
  for (const t of times) {
    const last = kept[kept.length - 1];
    if (
      t.at >= newest.at - KEPT_SECONDS &&
      (last === undefined || t.ledger - last.ledger >= MIN_SPAN)
    ) {
      kept.push(t);
    }
  }
  state.ledgerTimes = kept;
  return paceOf(times, newest);
}
