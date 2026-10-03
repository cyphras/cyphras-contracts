import type { ExitQueue } from "../net/indexer.ts";
import type { MetaEvent } from "../net/rpc.ts";
import { decodeVaultEvent } from "../vault/events.ts";
import type { ExitEvent } from "./sources.ts";
import type { Plan, PlanState, WalletState } from "./state.ts";

// The vault's FIFO exit queue: a transact pays at once only when the queue is empty and the
// day's outflow window has room; otherwise its payout waits for a permissionless release, and a
// payout the asset contract refuses then becomes stranded until someone claims it.

// What a transact's own events say about its payout: paid inside the transaction, or queued
// with an exit ID.
export function payoutFromEvents(
  events: readonly MetaEvent[],
  vault: string,
): { readonly kind: "settled" } | { readonly kind: "queued"; readonly id: number } | undefined {
  for (const event of events) {
    if (event.contractId !== vault) continue;
    const decoded = decodeVaultEvent(event);
    if (decoded.kind === "settled") return { kind: "settled" };
    if (decoded.kind === "exit_queued") return { kind: "queued", id: decoded.id };
  }
  return undefined;
}

const exitPlans = (state: WalletState): Plan[] =>
  state.plans.filter(
    (p) => p.kind === "unshield" && ["confirmed", "queued", "stranded"].includes(p.state),
  );

// Events and the indexer can lag each other, so a payout's state only moves forward.
const PROGRESS: Partial<Record<PlanState, number>> = {
  confirmed: 0,
  queued: 1,
  stranded: 2,
  settled: 3,
  claimed: 3,
};

function advance(plan: Plan, state: PlanState): void {
  if ((PROGRESS[state] ?? 0) > (PROGRESS[plan.state] ?? 0)) plan.state = state;
}

// The vault's own events, in chain order: exit_queued names the exit of a transaction, settled
// pays a transaction at once or completes an exit, and exit_stranded sets one aside for a claim.
function applyExitEvents(plans: readonly Plan[], events: readonly ExitEvent[]): void {
  for (const event of events) {
    if (event.kind === "exit_queued") {
      const plan = plans.find((p) => p.txHash === event.txHash);
      if (plan === undefined) continue;
      plan.exitId = event.id;
      advance(plan, "queued");
      continue;
    }
    if (event.kind === "settled" && event.exitId === undefined) {
      const plan = plans.find((p) => p.txHash === event.txHash && p.exitId === undefined);
      if (plan !== undefined) advance(plan, "settled");
      continue;
    }
    const id = event.kind === "settled" ? event.exitId : event.id;
    const plan = plans.find((p) => p.exitId === id);
    if (plan === undefined) continue;
    if (event.kind === "exit_stranded") advance(plan, "stranded");
    else advance(plan, plan.state === "stranded" ? "claimed" : "settled");
  }
}

// The indexer's view of the queue. A plan learns its exit ID from the queued entry of its
// transaction, and an exit below the head that is not stranded has been paid.
function applyExitQueue(state: WalletState, plans: readonly Plan[], queue: ExitQueue): void {
  const taken = new Set(state.plans.flatMap((p) => (p.exitId === undefined ? [] : [p.exitId])));
  for (const plan of plans) {
    if (plan.exitId === undefined) {
      const entry = queue.queued.find((e) => e.txHash === plan.txHash);
      if (entry !== undefined) {
        plan.exitId = entry.id;
        advance(plan, "queued");
        continue;
      }
      if (plan.ledger === undefined || queue.completeTo < plan.ledger) continue;
      // The indexer has seen the transaction and its exit is not queued: it was paid at once, or
      // queued and released since. Stranded entries name no transaction, so a released payout
      // the asset contract refused is recognized by its recipient and amount.
      const stranded = queue.stranded.find(
        (e) => !taken.has(e.id) && e.recipient === plan.to && e.payout === plan.amount,
      );
      if (stranded === undefined) {
        advance(plan, "settled");
        continue;
      }
      plan.exitId = stranded.id;
      taken.add(stranded.id);
      advance(plan, "stranded");
      continue;
    }
    const id = plan.exitId;
    if (queue.queued.some((e) => e.id === id)) continue;
    if (queue.stranded.some((e) => e.id === id)) advance(plan, "stranded");
    else if (id < queue.head) advance(plan, plan.state === "stranded" ? "claimed" : "settled");
  }
}

// Moves confirmed unshields to queued, stranded, settled or claimed, from the vault's events
// that RPC returned in this sync and from the indexer's queue. A transfer is settled once it is
// confirmed: its payment is the note, and a queued fee concerns only the relayer.
export function applyExits(
  state: WalletState,
  events: readonly ExitEvent[],
  queue: ExitQueue | undefined,
): void {
  for (const plan of state.plans) {
    if (plan.kind === "send" && plan.state === "confirmed") plan.state = "settled";
  }
  const plans = exitPlans(state);
  applyExitEvents(plans, events);
  if (queue !== undefined) applyExitQueue(state, plans, queue);
}

/** Where a queued payout stands in the vault's exit queue, by the indexer's account of it. */
export interface ExitPosition {
  readonly exitId: number;
  // Queued payouts paid before it.
  readonly ahead: number;
  readonly aheadAmount: bigint;
  // Unix seconds: the earliest time a release can pay it, if every exit ahead is released as
  // soon as it fits. Claims of stranded exits use the same window, so it can come later.
  readonly earliestRelease: number;
  // A release now would pay it.
  readonly dueNow: boolean;
}

export function exitPosition(
  queue: ExitQueue,
  exitId: number,
  nowSeconds: number,
): ExitPosition | undefined {
  const ahead = queue.queued.findIndex((e) => e.id === exitId);
  const mine = queue.queued[ahead];
  if (mine === undefined) return undefined;
  return {
    exitId,
    ahead,
    aheadAmount: queue.queued.slice(0, ahead).reduce((s, e) => s + e.payout + e.fee, 0n),
    earliestRelease: mine.earliestRelease,
    dueNow: mine.earliestRelease <= nowSeconds,
  };
}
