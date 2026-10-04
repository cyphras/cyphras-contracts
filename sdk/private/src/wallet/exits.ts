import type { ExitQueue } from "../net/indexer.ts";
import type { ExitEvent, ExitEvents } from "./sources.ts";
import type { ExitPart, Plan, PlanExit, WalletState } from "./state.ts";

// The vault's FIFO exit queue: a transact pays at once only when the queue is empty and the
// day's outflow window has room; otherwise its payout waits for a permissionless release. Release
// pays the head exit as far as the window reaches, payout first, so an exit can be paid in parts
// over several days. A part the asset contract refuses strands the exit with what it still owes;
// a claim moves the parts whose party can receive again back to the tail of the queue as a new
// exit, which release then pays like any other.

// Unshields whose exit can still move, among them those settled on the indexer's word alone.
const exitPlans = (state: WalletState): Plan[] =>
  state.plans.filter(
    (p) =>
      p.kind === "unshield" &&
      (["confirmed", "queued", "stranded"].includes(p.state) ||
        (p.state === "settled" &&
          p.exit !== undefined &&
          (!p.exit.confirmed || p.exit.account !== undefined))),
  );

// The parts of an exit that still owe, as the plan shows them: the indexer's newer account while it
// stands, else what the vault's events show.
export const shownParts = (exit: PlanExit): readonly ExitPart[] =>
  (exit.account?.parts ?? exit.parts).filter((p) => p.payoutLeft > 0n || p.feeLeft > 0n);

// An unshield is settled once its payout is paid in full, queued while all of what it still owes
// waits in the queue, and stranded while part of its payout waits for a claim. A fee left owed
// concerns only the relayer.
function settle(plan: Plan, exit: PlanExit): void {
  const owing = shownParts(exit).filter((p) => p.payoutLeft > 0n);
  if (owing.length === 0) plan.state = "settled";
  else plan.state = owing.some((p) => p.stranded) ? "stranded" : "queued";
}

const part = (exit: PlanExit, id: number): ExitPart | undefined =>
  exit.parts.find((p) => p.id === id);

const owed = (parts: readonly ExitPart[]): bigint =>
  parts.reduce((s, p) => s + p.payoutLeft + p.feeLeft, 0n);

function applied(exit: PlanExit, event: ExitEvent): boolean {
  if (event.ledger !== exit.ledger) return event.ledger < exit.ledger;
  return exit.event === undefined || event.eventId <= exit.event;
}

const less = (owed: bigint, moved: bigint): bigint => (owed > moved ? owed - moved : 0n);

// Applies one of the vault's events to the exit `p` it concerns, which holds or held part of the
// plan's: what the event shows of an exit replaces what the wallet knew of it. A part that missed
// earlier events may owe less than a claim moved from it, and then owes nothing more.
function apply(plan: Plan, exit: PlanExit, p: ExitPart, event: ExitEvent): void {
  switch (event.kind) {
    case "exit_paid":
    case "exit_stranded":
      p.payoutLeft = event.payoutLeft;
      p.feeLeft = event.feeLeft;
      if (event.kind === "exit_stranded") p.stranded = true;
      break;
    case "exit_requeued": {
      p.payoutLeft = less(p.payoutLeft, event.payout);
      p.feeLeft = less(p.feeLeft, event.fee);
      const moved = {
        id: event.newId,
        payoutLeft: event.payout,
        feeLeft: event.fee,
        stranded: false,
      };
      exit.parts = [...exit.parts.filter((x) => x.id !== event.newId), moved];
      break;
    }
    case "settled":
      p.payoutLeft = 0n;
      p.feeLeft = 0n;
      break;
    case "exit_queued":
      return;
  }
  exit.ledger = event.ledger;
  exit.event = event.eventId;
  settle(plan, exit);
}

// The first ledger of which an exit may not have followed every event yet.
const unfollowed = (exit: PlanExit): number =>
  exit.event === undefined ? exit.ledger + 1 : exit.ledger;

// The vault's own events, in chain order. exit_queued names the exit of a transaction, and every
// later event of that exit, or of the exits a claim requeues its parts as, is applied once.
function applyExitEvents(plans: readonly Plan[], exits: ExitEvents): void {
  // Events that do not follow on from what an exit followed leave a gap whose events it may never
  // see: from then on the exit rests on the indexer's account, of the gap where it has one.
  if (exits.from <= exits.to) {
    for (const plan of plans) {
      const exit = plan.exit;
      if (exit === undefined || exits.from <= unfollowed(exit)) continue;
      if (exit.account !== undefined) {
        const shown = exit.account.parts;
        exit.parts = [...shown, ...exit.parts.filter((p) => !shown.some((x) => x.id === p.id))];
        exit.ledger = exit.account.ledger;
        exit.event = undefined;
        exit.account = undefined;
      }
      exit.confirmed = false;
    }
  }
  for (const event of exits.events) {
    if (event.kind === "exit_queued") {
      const plan = plans.find((p) => p.txHash === event.txHash);
      if (plan === undefined || plan.exit?.confirmed === true) continue;
      // An exit the indexer's account alone showed takes the events from its queueing on, and that
      // account stands while it is newer than they are.
      const before = plan.exit;
      const exit: PlanExit = {
        id: event.id,
        parts: [{ id: event.id, payoutLeft: event.payout, feeLeft: event.fee, stranded: false }],
        ledger: event.ledger,
        event: event.eventId,
        confirmed: true,
        account:
          before === undefined || before.ledger <= event.ledger
            ? undefined
            : { parts: before.parts, ledger: before.ledger },
      };
      plan.exit = exit;
      settle(plan, exit);
      continue;
    }
    const id = event.kind === "settled" ? event.exitId : event.id;
    if (id === undefined) {
      // transact paid at once, so an exit the indexer's account alone gave the plan never was
      const plan = plans.find((p) => p.txHash === event.txHash && p.exit?.confirmed !== true);
      if (plan !== undefined) {
        plan.exit = undefined;
        plan.state = "settled";
      }
      continue;
    }
    for (const plan of plans) {
      const exit = plan.exit;
      const p = exit === undefined ? undefined : part(exit, id);
      if (exit !== undefined && p !== undefined && !applied(exit, event)) {
        apply(plan, exit, p, event);
      }
    }
  }
  // The events hold every ledger from `from` to `to`, so an exit followed up to one of them, or
  // through the whole ledger before `from`, is now followed up to `to`. An account of the
  // indexer's they now reach stands no more.
  for (const plan of plans) {
    const exit = plan.exit;
    if (exit === undefined) continue;
    if (exits.from <= unfollowed(exit) && exit.ledger <= exits.to) {
      exit.ledger = exits.to;
      exit.event = undefined;
    }
    if (exit.account !== undefined && exit.account.ledger <= exit.ledger) {
      exit.account = undefined;
      settle(plan, exit);
    }
  }
}

// The indexer's account of an exit as of the ledger it is complete to: every exit the wallet knows
// to hold part of it, and those claims queued from them, with what each owes then. An exit the
// indexer lists as settled, or as requeued in full, owes nothing; one it no longer lists keeps
// what the wallet knew of it, unless an exit queued from it is listed, which shows that claims
// moved all it owed. An account in which an exit owes more than the wallet knew, or a stranded
// exit is back in the queue or settled, contradicts the vault and is not taken.
function account(exit: PlanExit, queue: ExitQueue): ExitPart[] | undefined {
  const entries = new Map(queue.exits.map((e) => [e.id, e]));
  const parts: ExitPart[] = [];
  const seen = new Set<number>();
  const visit = (id: number, known: ExitPart | undefined): void => {
    if (seen.has(id)) return;
    seen.add(id);
    const entry = entries.get(id);
    const moved = queue.exits.filter((e) => e.requeuedFrom === id).map((e) => e.id);
    for (const next of [...(entry?.requeuedTo ?? []), ...moved]) visit(next, undefined);
    if (entry === undefined) {
      if (known === undefined) return;
      parts.push(moved.length === 0 ? { ...known } : { ...known, payoutLeft: 0n, feeLeft: 0n });
    } else {
      const done = entry.state === "settled" || entry.state === "requeued";
      parts.push({
        id,
        payoutLeft: done ? 0n : entry.payoutLeft,
        feeLeft: done ? 0n : entry.feeLeft,
        stranded: entry.state === "stranded" || entry.state === "requeued",
      });
    }
  };
  for (const p of exit.parts) visit(p.id, p);
  const contradicts = parts.some((p) => {
    const known = part(exit, p.id);
    return (
      known !== undefined &&
      (p.payoutLeft > known.payoutLeft ||
        p.feeLeft > known.feeLeft ||
        (known.stranded && !p.stranded))
    );
  });
  if (contradicts || owed(parts) > owed(exit.parts)) return undefined;
  return parts.sort((a, b) => a.id - b.id);
}

// The indexer's account of the queue, for what the vault's events of this sync did not cover. A
// plan learns its exit ID only from the queued entry of its own transaction; from then on the
// account is taken only when it is newer than what the plan's exit follows. It never moves how
// far a confirmed exit follows the vault's events, which take over once they reach its ledger.
function applyExitQueue(plans: readonly Plan[], queue: ExitQueue): void {
  for (const plan of plans) {
    if (plan.exit === undefined) {
      // paid at once, as the vault's events show
      if (plan.state === "settled") continue;
      const entry = queue.exits.find((e) => e.txHash === plan.txHash && e.position !== undefined);
      if (entry === undefined) continue;
      plan.exit = {
        id: entry.id,
        parts: [
          { id: entry.id, payoutLeft: entry.payoutLeft, feeLeft: entry.feeLeft, stranded: false },
        ],
        ledger: queue.completeTo,
        event: undefined,
        confirmed: false,
        account: undefined,
      };
      settle(plan, plan.exit);
      continue;
    }
    const exit = plan.exit;
    if (queue.completeTo <= (exit.account?.ledger ?? exit.ledger)) continue;
    const parts = account(exit, queue);
    if (parts === undefined) continue;
    if (exit.confirmed) {
      exit.account = { parts, ledger: queue.completeTo };
    } else {
      exit.parts = parts;
      exit.ledger = queue.completeTo;
      exit.event = undefined;
    }
    settle(plan, exit);
  }
}

// Moves confirmed unshields to queued, stranded or settled, from the vault's events of the
// ledgers this sync checked against every RPC provider, in chain order, and from the indexer's
// queue, which counts only when it is complete to no later than `latest`, the ledger the vault was
// read at. A transfer is settled once it is confirmed: its payment is the note, and a queued fee
// concerns only the relayer.
export function applyExits(
  state: WalletState,
  exits: readonly ExitEvents[],
  queue: ExitQueue | undefined,
  latest: number,
): void {
  for (const plan of state.plans) {
    if (plan.kind === "send" && plan.state === "confirmed") plan.state = "settled";
  }
  const plans = exitPlans(state);
  for (const events of exits) applyExitEvents(plans, events);
  if (queue !== undefined && queue.completeTo <= latest) applyExitQueue(plans, queue);
}

// What an unshield's exit still owes its recipient, over every exit that holds part of it.
export const payoutLeft = (exit: PlanExit): bigint =>
  shownParts(exit).reduce((s, p) => s + p.payoutLeft, 0n);

/** Where a queued payout stands in the vault's exit queue, by the indexer's account of it. */
export interface ExitPosition {
  readonly exitId: number;
  // Queued exits paid before it, and what they still owe.
  readonly ahead: number;
  readonly aheadAmount: bigint;
  // What this exit still owes to its recipient and its relayer.
  readonly payoutLeft: bigint;
  readonly feeLeft: bigint;
  // The first part of the payout creates the recipient's account. Release pays no such part below
  // the account's minimum balance, and leaves the rest of a shorter window unused.
  readonly createsAccount: boolean;
  // Unix seconds: the end of the UTC day by which releases have paid it at the latest, which
  // allows for exits whose first part waits for a window that can create the account. Halts can
  // make it later.
  readonly paidBy: number;
}

export function exitPosition(
  queue: ExitQueue,
  exitId: number,
  createsAccount: boolean,
): ExitPosition | undefined {
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
    createsAccount,
    paidBy: mine.paidBy,
  };
}
