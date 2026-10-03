import type { ExitEntry, ExitQueue } from "../net/indexer.ts";
import type { ExitEvent } from "./sources.ts";
import type { Plan, PlanExit, PlanState, WalletState } from "./state.ts";

// The vault's FIFO exit queue: a transact pays at once only when the queue is empty and the
// day's outflow window has room; otherwise its payout waits for a permissionless release. Release
// pays the head exit as far as the window reaches, payout first, so an exit can be paid in parts
// over several days. A part the asset contract refuses strands the exit with what it still owes,
// until a claim pays each part.

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

// What an exit owes only ever shrinks, so an older report never raises it again.
function owes(exit: PlanExit, payoutLeft: bigint, feeLeft: bigint): void {
  if (payoutLeft + feeLeft <= exit.payoutLeft + exit.feeLeft) {
    exit.payoutLeft = payoutLeft;
    exit.feeLeft = feeLeft;
  }
}

function paidInFull(plan: Plan & { exit: PlanExit }): void {
  owes(plan.exit, 0n, 0n);
  advance(plan, plan.state === "stranded" ? "claimed" : "settled");
}

const open = (plan: Plan): boolean => plan.state !== "settled" && plan.state !== "claimed";

// The vault's own events, in chain order. exit_queued names the exit of a transaction; settled
// pays a transaction at once or completes an exit; exit_paid and exit_stranded report what an exit
// still owes.
function applyExitEvents(plans: readonly Plan[], events: readonly ExitEvent[]): void {
  const byExit = (id: number): (Plan & { exit: PlanExit }) | undefined =>
    plans.find((p): p is Plan & { exit: PlanExit } => p.exit?.id === id);
  for (const event of events) {
    switch (event.kind) {
      case "exit_queued": {
        const plan = plans.find((p) => p.txHash === event.txHash);
        if (plan === undefined || plan.exit !== undefined) break;
        plan.exit = { id: event.id, payoutLeft: event.payout, feeLeft: event.fee };
        advance(plan, "queued");
        break;
      }
      case "settled": {
        if (event.exitId === undefined) {
          const plan = plans.find((p) => p.txHash === event.txHash && p.exit === undefined);
          if (plan !== undefined) advance(plan, "settled");
          break;
        }
        const plan = byExit(event.exitId);
        if (plan !== undefined && open(plan)) paidInFull(plan);
        break;
      }
      case "exit_paid":
      case "exit_stranded": {
        const plan = byExit(event.id);
        if (plan === undefined || !open(plan)) break;
        owes(plan.exit, event.payoutLeft, event.feeLeft);
        if (event.kind === "exit_stranded") advance(plan, "stranded");
        break;
      }
    }
  }
}

// The indexer's view of the queue, for exits whose events this wallet did not see. A plan learns
// its exit ID only from the entry of its own transaction, and an exit's state is matched by ID.
function applyExitQueue(plans: readonly Plan[], queue: ExitQueue): void {
  for (const plan of plans) {
    const entry: ExitEntry | undefined =
      plan.exit === undefined
        ? queue.exits.find((e) => e.txHash === plan.txHash)
        : queue.exits.find((e) => e.id === plan.exit?.id);
    if (entry === undefined) continue;
    plan.exit ??= { id: entry.id, payoutLeft: entry.payoutLeft, feeLeft: entry.feeLeft };
    if (!open(plan)) continue;
    owes(plan.exit, entry.payoutLeft, entry.feeLeft);
    if (entry.state === "stranded") advance(plan, "stranded");
    else if (entry.state === "settled") paidInFull(plan as Plan & { exit: PlanExit });
    else advance(plan, "queued");
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
  if (queue !== undefined) applyExitQueue(plans, queue);
}

/** Where a queued payout stands in the vault's exit queue, by the indexer's account of it. */
export interface ExitPosition {
  readonly exitId: number;
  // Queued exits paid before it, and what they still owe.
  readonly ahead: number;
  readonly aheadAmount: bigint;
  // What this exit still owes to its recipient and its relayer.
  readonly payoutLeft: bigint;
  readonly feeLeft: bigint;
  // Unix seconds: the end of the UTC day by which releases have paid it at the latest. Claims of
  // stranded exits and halts can make it later.
  readonly paidBy: number;
}

export function exitPosition(queue: ExitQueue, exitId: number): ExitPosition | undefined {
  const mine = queue.exits.find((e) => e.id === exitId);
  if (mine?.position === undefined || mine.paidBy === undefined) return undefined;
  const position = mine.position;
  return {
    exitId,
    ahead: position,
    aheadAmount: queue.exits
      .filter((e) => e.position !== undefined && e.position < position)
      .reduce((s, e) => s + e.payoutLeft + e.feeLeft, 0n),
    payoutLeft: mine.payoutLeft,
    feeLeft: mine.feeLeft,
    paidBy: mine.paidBy,
  };
}
