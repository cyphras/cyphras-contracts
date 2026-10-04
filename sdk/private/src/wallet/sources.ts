import { CyphrasError, fail } from "../errors.ts";
import type { IndexerClient, Leaf, SpentNullifier } from "../net/indexer.ts";
import type { SorobanRpc } from "../net/rpc.ts";
import { type CommitmentTree, PAGE_SIZE } from "../merkle.ts";
import { type VaultEvent, decodeVaultEvent } from "../vault/events.ts";
import type { LedgerTime } from "./state.ts";

export interface LeafBatch {
  // The leaves after the tree's last one, in index order.
  readonly leaves: readonly Leaf[];
  readonly done: boolean;
}

export interface NullifierSet {
  readonly nullifiers: readonly SpentNullifier[];
  readonly completeToLedger: number;
}

/**
 * How much one sync downloads at most, in pages: of 1,024 leaves, of the indexer's nullifiers and
 * of RPC's events. A sync that stops at a cap keeps what it could check and continues next time.
 */
export interface SyncLimits {
  readonly leafPages: number;
  readonly nullifierPages: number;
  readonly eventPages: number;
}

export const DEFAULT_SYNC_LIMITS: SyncLimits = {
  leafPages: 64,
  nullifierPages: 64,
  eventPages: 100,
};

// Where a sync reads the vault's leaves and spent nullifiers from. Both kinds download whole
// pages or ranges, so no request names a note.
export interface ChainSource {
  readonly kind: "indexer" | "rpc";
  nextLeaves(tree: CommitmentTree): Promise<LeafBatch>;
  nullifiers(sinceLedger: number): Promise<NullifierSet>;
}

export class IndexerSource implements ChainSource {
  readonly kind = "indexer";
  readonly #indexer: IndexerClient;
  readonly #maxPages: number;

  constructor(indexer: IndexerClient, maxPages: number) {
    this.#indexer = indexer;
    this.#maxPages = maxPages;
  }

  // Asks for the page of the next leaf, from its start, so the request shows only how far the
  // wallet has synced. The leaves it already holds must come back unchanged.
  async nextLeaves(tree: CommitmentTree): Promise<LeafBatch> {
    const served = await this.#indexer.leaves(tree.currentPage);
    const known = tree.partialLeaves;
    if (served.length < known.length)
      fail("indexer_fault", "the indexer served fewer leaves than before");
    known.forEach((cm, i) => {
      if (served[i]?.commitment !== cm)
        fail("indexer_fault", "the indexer changed a leaf it served before");
    });
    return { leaves: served.slice(known.length), done: served.length < PAGE_SIZE };
  }

  async nullifiers(sinceLedger: number): Promise<NullifierSet> {
    const nullifiers: SpentNullifier[] = [];
    let cursor: string | undefined;
    let completeToLedger = sinceLedger - 1;
    for (let pages = 1; ; pages++) {
      const page = await this.#indexer.nullifiers(sinceLedger, cursor);
      nullifiers.push(...page.nullifiers);
      completeToLedger = page.completeToLedger;
      if (page.cursor === undefined) break;
      if (pages === this.#maxPages) {
        // In chain order, every ledger before the last one listed is complete.
        completeToLedger = (nullifiers[nullifiers.length - 1]?.ledger ?? sinceLedger) - 1;
        break;
      }
      cursor = page.cursor;
    }
    // A nullifier ingested after the indexer read its complete-to ledger may already be listed;
    // the next sync, which asks from the ledger after, receives it again.
    return { nullifiers: nullifiers.filter((n) => n.ledger <= completeToLedger), completeToLedger };
  }
}

const EVENT_PAGE = 1000;

// A vault event that moves an exit along, with the transaction that emitted it.
export type ExitEvent = Extract<
  VaultEvent,
  { kind: "exit_queued" | "exit_paid" | "exit_stranded" | "exit_requeued" | "settled" }
> & {
  // RPC's ID of the event, which orders events across ledgers and within one.
  readonly eventId: string;
  readonly txHash: string;
  readonly ledger: number;
};

// The vault's exit events of every ledger from `from` to `to`.
export interface ExitEvents {
  readonly from: number;
  readonly to: number;
  readonly events: readonly ExitEvent[];
}

// A deposit the vault took into its entry queue, with the transaction that made it.
export type DepositEvent = Extract<VaultEvent, { kind: "deposit_pending" }> & {
  readonly txHash: string;
  readonly ledger: number;
};

export interface VaultEvents {
  readonly leaves: Leaf[];
  readonly nullifiers: SpentNullifier[];
  readonly exits: ExitEvent[];
  readonly deposits: DepositEvent[];
  // The events are complete from `from` up to `latest`; `head` is the latest ledger RPC knows of.
  readonly from: number;
  readonly latest: number;
  readonly head: number;
  // Close times RPC reported: of the oldest ledger it holds, of the first event's ledger and of
  // the head.
  readonly times: readonly LedgerTime[];
}

// What a read of the vault's events needs no more of: the events after a ledger, once the leaves
// before a position are in, when it names one.
export interface EventsEnd {
  readonly ledger: number;
  readonly leafEnd: number | undefined;
}

// Where a getEvents cursor or event ID stands: its TOID and event index, in the order RPC pages in;
// its ledger, the TOID shifted right by 32 bits; and whether it closes that ledger, as the cursor of
// a scan that stopped there does, with the largest transaction, operation and event index.
interface Position {
  readonly toid: bigint;
  readonly event: bigint;
  readonly ledger: number;
  readonly closes: boolean;
}

function position(id: string): Position | undefined {
  const parts = /^(\d{1,19})-(\d{1,10})$/.exec(id);
  if (parts === null) return undefined;
  const toid = BigInt(parts[1] as string);
  const event = BigInt(parts[2] as string);
  return {
    toid,
    event,
    ledger: Number(toid >> 32n),
    closes: (toid & 0xffffffffn) === 0xffffffffn && event === 0xffffffffn,
  };
}

const after = (a: Position, b: Position): boolean =>
  a.toid > b.toid || (a.toid === b.toid && a.event > b.event);

// The fallback when no indexer is available: the vault's own events from RPC, which keeps them
// for about a week. A wallet further behind than that cannot sync this way. RPC scans a bounded
// range of ledgers per request, so a short page says nothing of the ledgers after it: the read
// follows the cursor until it covers the latest ledger, and counts as covered only the ledgers the
// cursor shows were scanned. A read with an end stops once it covers that end.
export class RpcEventSource implements ChainSource {
  readonly kind = "rpc";
  readonly #rpc: SorobanRpc;
  readonly #vault: string;
  readonly #startLedger: number;
  readonly #maxPages: number;
  readonly #end: EventsEnd | undefined;
  #loaded: Promise<VaultEvents> | undefined;

  constructor(
    rpc: SorobanRpc,
    vault: string,
    startLedger: number,
    maxPages: number,
    end?: EventsEnd,
  ) {
    this.#rpc = rpc;
    this.#vault = vault;
    this.#startLedger = startLedger;
    this.#maxPages = maxPages;
    this.#end = end;
  }

  async #load(): Promise<VaultEvents> {
    const leaves: Leaf[] = [];
    const nullifiers: SpentNullifier[] = [];
    const exits: ExitEvent[] = [];
    const deposits: DepositEvent[] = [];
    const times: LedgerTime[] = [];
    const time = (ledger: number, at: number | undefined): void => {
      if (at !== undefined) times.push({ ledger, at });
    };
    let cursor: string | undefined;
    let at: Position | undefined;
    // The last ledger every ledger up to which was scanned.
    let covered = this.#startLedger - 1;
    let head = this.#startLedger;
    let headTime: number | undefined;
    // The position after the last leaf read.
    let leafEnd = 0;
    for (let pages = 1; ; pages++) {
      let page;
      try {
        page = await this.#rpc.getEvents({
          contractId: this.#vault,
          ...(cursor === undefined ? { startLedger: this.#startLedger } : { cursor }),
          limit: EVENT_PAGE,
        });
      } catch (err) {
        // RPC refuses a start ledger outside the range it holds as an invalid request.
        if (err instanceof CyphrasError && cursor === undefined && err.details["code"] === -32600) {
          fail("history_unavailable", "RPC no longer holds the vault events this wallet needs");
        }
        throw err;
      }
      if (cursor === undefined && page.oldestLedger > this.#startLedger) {
        fail("history_unavailable", "RPC no longer holds the vault events this wallet needs");
      }
      if (cursor === undefined) {
        time(page.oldestLedger, page.oldestCloseTime);
        const first = page.events[0];
        if (first !== undefined) time(first.ledger, first.closedAt);
      }
      head = page.latestLedger;
      headTime = page.latestCloseTime;
      for (const event of page.events) {
        if (!event.successful || event.contractId !== this.#vault) continue;
        const decoded = decodeVaultEvent(event);
        if (decoded.kind === "new_commitment") {
          leafEnd = Math.max(leafEnd, decoded.index + 1);
          leaves.push({
            index: decoded.index,
            commitment: decoded.commitment,
            ciphertext: decoded.ciphertext,
            ledger: event.ledger,
            txHash: event.txHash,
          });
        } else if (decoded.kind === "new_nullifier") {
          nullifiers.push({
            nullifier: decoded.nullifier,
            ledger: event.ledger,
            txHash: event.txHash,
          });
        } else if (
          decoded.kind === "exit_queued" ||
          decoded.kind === "exit_paid" ||
          decoded.kind === "exit_stranded" ||
          decoded.kind === "exit_requeued" ||
          decoded.kind === "settled"
        ) {
          exits.push({ ...decoded, eventId: event.id, txHash: event.txHash, ledger: event.ledger });
        } else if (decoded.kind === "deposit_pending") {
          deposits.push({ ...decoded, txHash: event.txHash, ledger: event.ledger });
        }
      }
      const next = page.cursor === undefined ? undefined : position(page.cursor);
      if (next === undefined) {
        fail("rpc_error", "the RPC's events came without a cursor to go on from");
      }
      // A cursor that does not move on leaves the rest of the range unscanned.
      if (at !== undefined && !after(next, at)) break;
      at = next;
      // A full page stops inside the ledger of its last event, which is covered only once a later
      // page closes it.
      covered = Math.max(covered, next.closes ? next.ledger : next.ledger - 1);
      const end = this.#end;
      const past =
        end !== undefined && covered >= end.ledger && leafEnd >= (end.leafEnd ?? leafEnd);
      if (covered >= head || past || pages === this.#maxPages) break;
      cursor = page.cursor;
    }
    const latest = Math.min(covered, head);
    time(head, headTime);
    const upTo = <T extends { readonly ledger: number }>(xs: T[]): T[] =>
      xs.filter((x) => x.ledger <= latest);
    return {
      leaves: upTo(leaves).sort((a, b) => a.index - b.index),
      nullifiers: upTo(nullifiers),
      exits: upTo(exits),
      deposits: upTo(deposits),
      from: this.#startLedger,
      latest,
      head,
      times,
    };
  }

  events(): Promise<VaultEvents> {
    this.#loaded ??= this.#load();
    return this.#loaded;
  }

  async nextLeaves(tree: CommitmentTree): Promise<LeafBatch> {
    const { leaves } = await this.events();
    const fresh = leaves.filter((l) => l.index >= tree.leafCount);
    fresh.forEach((leaf, i) => {
      if (leaf.index !== tree.leafCount + i) {
        fail("history_unavailable", "the RPC events leave a gap in the leaves");
      }
    });
    return { leaves: fresh, done: true };
  }

  async nullifiers(sinceLedger: number): Promise<NullifierSet> {
    const { nullifiers, latest } = await this.events();
    if (sinceLedger < this.#startLedger) {
      fail("history_unavailable", "RPC no longer holds the nullifiers this wallet needs");
    }
    return {
      nullifiers: nullifiers.filter((n) => n.ledger >= sinceLedger),
      completeToLedger: latest,
    };
  }
}
