import { confirmedInputs, lockedPositions, spendableNotes } from "./core.ts";
import type { WalletState } from "./state.ts";

/** Spendable value, value in pending deposits, value locked in unconfirmed submissions. */
export interface Balance {
  readonly spendable: bigint;
  readonly pendingDeposits: bigint;
  readonly locked: bigint;
  // Unshields confirmed on chain whose payout waits in the vault's exit queue or is stranded.
  readonly awaitingPayout: bigint;
  // True for a wallet with only an incoming viewing key, which cannot see spends.
  readonly spendsUnknown: boolean;
}

export function balanceOf(state: WalletState, spendsVisible: boolean): Balance {
  const spendable = spendableNotes(state).reduce((s, n) => s + n.value, 0n);
  const locked = lockedPositions(state);
  return {
    spendable,
    pendingDeposits: state.deposits
      .filter((d) => d.state === "pending" || d.state === "submitting")
      .reduce((s, d) => s + d.amount, 0n),
    locked: state.notes.filter((n) => locked.has(n.pos)).reduce((s, n) => s + n.value, 0n),
    awaitingPayout: state.plans
      .filter((p) => p.state === "queued" || p.state === "stranded")
      .reduce((s, p) => s + p.amount, 0n),
    spendsUnknown: !spendsVisible,
  };
}

export type HistoryKind = "shield" | "cancel" | "refund" | "receive" | "send" | "unshield" | "self";

/** One entry of the wallet's history. */
export interface HistoryEntry {
  readonly kind: HistoryKind;
  readonly amount: bigint;
  // Undefined when only the chain is known and it does not separate fee from amount.
  readonly fee: bigint | undefined;
  // The shielded address paid, the Stellar address unshielded to, or the depositor.
  readonly counterparty: string | undefined;
  readonly txHash: string | undefined;
  readonly ledger: number | undefined;
  // Milliseconds since the epoch, for operations this wallet made itself.
  readonly time: number | undefined;
  readonly state: string;
  readonly depositId: number | undefined;
  readonly leafIndex: number | undefined;
  // Rebuilt from the chain with the viewing keys, without a local record of the operation.
  readonly recovered: boolean;
}

const entry = (
  e: Partial<HistoryEntry> & Pick<HistoryEntry, "kind" | "amount" | "state">,
): HistoryEntry => ({
  fee: undefined,
  counterparty: undefined,
  txHash: undefined,
  ledger: undefined,
  time: undefined,
  depositId: undefined,
  leafIndex: undefined,
  recovered: false,
  ...e,
});

// Local records first: deposits and plans this wallet made. Every other transaction that
// touched the wallet is classified from what its keys reveal, which is what a restored wallet
// has: notes received, notes it built (outgoing key) and notes it spent (nullifiers).
export function historyOf(state: WalletState): HistoryEntry[] {
  const out: HistoryEntry[] = [];
  const covered = new Set<string>();
  const depositCommitments = new Set<bigint>();
  for (const d of state.deposits) {
    if (d.state === "failed") continue;
    d.commitments.forEach((cm) => depositCommitments.add(cm));
    out.push(
      entry({
        kind: "shield",
        amount: d.amount,
        fee: 0n,
        counterparty: d.depositor,
        txHash: d.txHash,
        time: d.createdAt,
        state: d.state,
        depositId: d.id,
      }),
    );
    if (d.state === "cancelled" || d.state === "refunded") {
      out.push(
        entry({
          kind: d.state === "cancelled" ? "cancel" : "refund",
          amount: d.amount,
          counterparty: d.depositor,
          state: d.state,
          depositId: d.id,
        }),
      );
    }
  }
  for (const plan of state.plans) {
    if (plan.state === "superseded" || plan.state === "dead") continue;
    if (plan.txHash !== undefined) covered.add(plan.txHash);
    out.push(
      entry({
        kind: plan.kind,
        amount: plan.amount,
        fee: plan.fee,
        counterparty: plan.to,
        txHash: plan.txHash,
        ledger: plan.ledger,
        time: plan.createdAt,
        state: plan.state,
      }),
    );
  }

  const planned = confirmedInputs(state);
  const txs = new Set<string>();
  for (const n of state.notes) {
    if (!depositCommitments.has(n.cm)) txs.add(n.txHash);
    if (n.spent !== undefined && !planned.has(n.pos)) txs.add(n.spent.txHash);
  }
  for (const s of state.sent) txs.add(s.txHash);
  for (const tx of txs) {
    if (covered.has(tx)) continue;
    const mine = state.notes.filter((n) => n.txHash === tx && !depositCommitments.has(n.cm));
    const sent = state.sent.filter((s) => s.txHash === tx);
    const spentIn = state.notes.filter((n) => n.spent?.txHash === tx);
    const ledger = mine[0]?.ledger ?? sent[0]?.ledger ?? spentIn[0]?.spent?.ledger;
    const sum = (xs: readonly { value: bigint }[]): bigint => xs.reduce((s, x) => s + x.value, 0n);
    if (spentIn.length === 0) {
      if (mine.length > 0 && sent.length === 0 && mine.every((n) => n.built)) {
        out.push(
          entry({
            kind: "shield",
            amount: sum(mine),
            txHash: tx,
            ledger,
            state: "admitted",
            recovered: true,
          }),
        );
        continue;
      }
      for (const n of mine.filter((m) => !m.built)) {
        out.push(
          entry({
            kind: "receive",
            amount: n.value,
            txHash: tx,
            ledger: n.ledger,
            leafIndex: n.pos,
            state: "confirmed",
            recovered: true,
          }),
        );
      }
      continue;
    }
    const outflow = sum(spentIn) - sum(mine) - sum(sent);
    if (sent.length > 0) {
      out.push(
        entry({
          kind: "send",
          amount: sum(sent),
          fee: outflow,
          counterparty: sent[0]?.address,
          txHash: tx,
          ledger,
          state: "confirmed",
          recovered: true,
        }),
      );
    } else {
      out.push(
        entry({
          kind: outflow > 0n ? "unshield" : "self",
          amount: outflow,
          txHash: tx,
          ledger,
          state: "confirmed",
          recovered: true,
        }),
      );
    }
  }
  return out.sort(
    (a, b) => (b.ledger ?? Infinity) - (a.ledger ?? Infinity) || (b.time ?? 0) - (a.time ?? 0),
  );
}
