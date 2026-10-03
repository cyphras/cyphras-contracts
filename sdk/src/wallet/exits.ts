import { scValToBigInt } from "@stellar/stellar-base";
import type { ExitEntry, ExitQueue } from "../net/indexer.ts";
import type { MetaEvent } from "../net/rpc.ts";
import type { VaultInstance } from "../vault/state.ts";
import type { Plan, WalletState } from "./state.ts";

// The vault's FIFO exit queue: a transact pays at once only when the queue is empty and the
// day's outflow window has room; otherwise its payout waits for a permissionless release, and a
// payout that cannot be delivered then becomes stranded until someone claims it.

// What a transact's own events say about its payout: paid inside the transaction, or queued
// with an exit id.
export function payoutFromEvents(
  events: readonly MetaEvent[],
  vault: string,
): { readonly kind: "settled" } | { readonly kind: "queued"; readonly id: number } | undefined {
  for (const event of events) {
    const [topic] = event.topic;
    if (event.contractId !== vault || topic?.switch().name !== "scvSymbol") continue;
    const name = topic.sym().toString();
    if (name === "settled") return { kind: "settled" };
    if (name !== "exit_queued") continue;
    for (const field of event.value.map() ?? []) {
      if (field.key().switch().name === "scvSymbol" && field.key().sym().toString() === "id") {
        return { kind: "queued", id: Number(scValToBigInt(field.val())) };
      }
    }
  }
  return undefined;
}

const exitPlans = (state: WalletState): Plan[] =>
  state.plans.filter(
    (p) => p.kind === "unshield" && ["confirmed", "queued", "stranded"].includes(p.state),
  );

// Moves confirmed unshields to settled, queued, stranded or claimed. A vault without an exit
// queue pays every unshield inside the transact. A transfer is settled once it is confirmed: its
// payment is the note, and a queued fee concerns only the relayer.
export function applyExits(
  state: WalletState,
  instance: VaultInstance,
  queue: ExitQueue | undefined,
): void {
  for (const plan of state.plans) {
    if (plan.kind === "send" && plan.state === "confirmed") plan.state = "settled";
  }
  const hasQueue = instance.status.exitHead !== undefined;
  for (const plan of exitPlans(state)) {
    if (!hasQueue) {
      if (plan.state === "confirmed") plan.state = "settled";
      continue;
    }
    if (queue === undefined) continue;
    const byTx = (e: { txHash: string }): boolean => e.txHash === plan.txHash;
    const queued = queue.queued.find(byTx);
    const stranded = queue.stranded.find(byTx);
    const resolved = queue.resolved.find(byTx);
    const id = queued?.id ?? stranded?.id ?? resolved?.id;
    if (id !== undefined) plan.exitId = id;
    if (resolved?.outcome === "paid") plan.state = "settled";
    else if (resolved?.outcome === "claimed") plan.state = "claimed";
    else if (stranded !== undefined || resolved?.outcome === "stranded") plan.state = "stranded";
    else if (queued !== undefined) plan.state = "queued";
    else if (plan.state === "confirmed" && queue.completeToLedger >= (plan.ledger ?? Infinity)) {
      // Never queued: the transact paid it.
      plan.state = "settled";
    }
  }
}

/** Where a queued payout stands, from the indexer's queue and the vault's outflow window. */
export interface ExitPosition {
  readonly exitId: number;
  // Queued payouts that are paid first.
  readonly ahead: number;
  readonly aheadAmount: bigint;
  // A release now would pay it.
  readonly dueNow: boolean;
  // Unix seconds: the start of the UTC day whose window pays it, if releases keep up.
  readonly estimatedAt: number;
}

const DAY = 86_400;

// Strict FIFO: each day's window pays queued exits in order until the next one does not fit.
export function exitPosition(
  queue: ExitQueue,
  exitId: number,
  instance: VaultInstance,
  nowSeconds: number,
): ExitPosition | undefined {
  const entries: ExitEntry[] = [...queue.queued].sort((a, b) => a.id - b.id);
  const mine = entries.findIndex((e) => e.id === exitId);
  if (mine < 0) return undefined;
  const { limits, status } = instance;
  let day = Math.floor(nowSeconds / DAY);
  let room =
    status.outflowDay === BigInt(day)
      ? limits.maxDailyOutflow - status.outflow
      : limits.maxDailyOutflow;
  let aheadAmount = 0n;
  for (let i = 0; i <= mine; i++) {
    const entry = entries[i] as ExitEntry;
    const outflow = entry.payout + entry.fee;
    if (outflow > room) {
      day++;
      room = limits.maxDailyOutflow;
    }
    room -= outflow;
    if (i < mine) aheadAmount += outflow;
  }
  const today = Math.floor(nowSeconds / DAY);
  return {
    exitId,
    ahead: mine,
    aheadAmount,
    dueNow: day === today,
    estimatedAt: day === today ? nowSeconds : day * DAY,
  };
}
