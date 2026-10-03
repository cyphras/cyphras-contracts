import { CyphrasError, fail } from "../errors.ts";
import type { IndexerClient, Leaf, SpentNullifier } from "../net/indexer.ts";
import type { SorobanRpc } from "../net/rpc.ts";
import { type CommitmentTree, PAGE_SIZE } from "../merkle.ts";
import { type VaultEvent, decodeVaultEvent } from "../vault/events.ts";

export interface LeafBatch {
  // The leaves after the tree's last one, in index order.
  readonly leaves: readonly Leaf[];
  readonly done: boolean;
}

export interface NullifierSet {
  readonly nullifiers: readonly SpentNullifier[];
  readonly completeToLedger: number;
}

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

  constructor(indexer: IndexerClient) {
    this.#indexer = indexer;
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
    for (;;) {
      const page = await this.#indexer.nullifiers(sinceLedger, cursor);
      nullifiers.push(...page.nullifiers);
      completeToLedger = page.completeToLedger;
      if (page.cursor === undefined) break;
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
  { kind: "exit_queued" | "exit_paid" | "exit_stranded" | "settled" }
> & {
  readonly txHash: string;
};

export interface VaultEvents {
  readonly leaves: Leaf[];
  readonly nullifiers: SpentNullifier[];
  readonly exits: ExitEvent[];
  readonly latest: number;
}

// The fallback when no indexer is available: the vault's own events from RPC, which keeps them
// for about a week. A wallet further behind than that cannot sync this way.
export class RpcEventSource implements ChainSource {
  readonly kind = "rpc";
  readonly #rpc: SorobanRpc;
  readonly #vault: string;
  readonly #startLedger: number;
  #loaded: Promise<VaultEvents> | undefined;

  constructor(rpc: SorobanRpc, vault: string, startLedger: number) {
    this.#rpc = rpc;
    this.#vault = vault;
    this.#startLedger = startLedger;
  }

  async #load(): Promise<VaultEvents> {
    const leaves: Leaf[] = [];
    const nullifiers: SpentNullifier[] = [];
    const exits: ExitEvent[] = [];
    let cursor: string | undefined;
    let latest = this.#startLedger;
    for (;;) {
      let page;
      try {
        page = await this.#rpc.getEvents({
          contractId: this.#vault,
          ...(cursor === undefined ? { startLedger: this.#startLedger } : { cursor }),
          limit: EVENT_PAGE,
        });
      } catch (err) {
        if (err instanceof CyphrasError && cursor === undefined) {
          fail("history_unavailable", "RPC no longer holds the vault events this wallet needs");
        }
        throw err;
      }
      if (cursor === undefined && page.oldestLedger > this.#startLedger) {
        fail("history_unavailable", "RPC no longer holds the vault events this wallet needs");
      }
      latest = page.latestLedger;
      for (const event of page.events) {
        if (!event.successful || event.contractId !== this.#vault) continue;
        const decoded = decodeVaultEvent(event);
        if (decoded.kind === "new_commitment") {
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
          decoded.kind === "settled"
        ) {
          exits.push({ ...decoded, txHash: event.txHash });
        }
      }
      if (page.events.length < EVENT_PAGE || page.cursor === undefined) break;
      cursor = page.cursor;
    }
    leaves.sort((a, b) => a.index - b.index);
    return { leaves, nullifiers, exits, latest };
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
