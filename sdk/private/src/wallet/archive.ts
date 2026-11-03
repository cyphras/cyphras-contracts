import { xdr } from "@stellar/stellar-base";
import { CyphrasError, fail } from "../errors.ts";
import {
  type ArchiveManifest,
  type ArchivePin,
  type ArchiveWindow,
  fetchManifest,
  fetchWindow,
} from "../net/archive.ts";
import type { FetchLike } from "../net/http.ts";
import type { Leaf, SpentNullifier } from "../net/indexer.ts";
import { type SorobanRpc, keyId } from "../net/rpc.ts";
import type { CommitmentTree } from "../merkle.ts";
import { type ChainView, type VaultReader, nullifierKey } from "../vault/state.ts";
import {
  type ArchivePart,
  type ChainSource,
  type LeafBatch,
  type NullifierSet,
  RpcEventSource,
  type VaultEvents,
} from "./sources.ts";

// getLedgerEntries takes at most this many keys.
const ENTRY_BATCH = 200;

export interface ArchiveSourceOptions {
  // Base URLs of copies of the archive, asked in order until one passes every check.
  readonly urls: readonly string[];
  readonly fetch: FetchLike;
  readonly pin: ArchivePin;
  // Every RPC provider: each must hold an entry for every nullifier taken from the archive, and
  // the first one's events carry the tree on from the archive's last ledger.
  readonly rpcs: readonly SorobanRpc[];
  readonly vaults: readonly VaultReader[];
  // The first ledger whose spends the sync asks for, and the leaves the tree it extends holds.
  readonly since: number;
  readonly leafCount: number;
  // How many windows with leaves, and with nullifiers, one sync reads at most, and the event pages
  // of RPC.
  readonly leafWindows: number;
  readonly nullifierWindows: number;
  readonly eventPages: number;
}

interface Loaded {
  readonly leaves: readonly Leaf[];
  readonly nullifiers: readonly SpentNullifier[];
  readonly completeTo: number;
  readonly part: ArchivePart;
  readonly tail: VaultEvents | undefined;
}

const reason = (err: CyphrasError): unknown => err.details["reason"];

// The fallback once RPC no longer holds where the wallet's sync starts: the vault's published
// archive, then RPC's events from the ledger after the archive's last one. Nothing the archive says
// about itself is taken on its word. Its manifest is refused before any window is read when it
// claims more leaves or later ledgers than any RPC provider shows the vault has; every nullifier
// taken from it must have an entry in the vault on every provider; and the tree it builds counts
// only under a root the vault holds, which the sync checks as for every other source. Leaves and
// spends only the archive shows cannot be checked any further, and the sync keeps them as lost.
export class ArchiveSource implements ChainSource {
  readonly kind = "archive";
  readonly #o: ArchiveSourceOptions;
  #loaded: Promise<Loaded> | undefined;

  constructor(options: ArchiveSourceOptions) {
    this.#o = options;
  }

  #load(): Promise<Loaded> {
    this.#loaded ??= this.#first();
    return this.#loaded;
  }

  // The first copy that passes. A copy that breaks a rule is passed over for the next one, and so
  // is one that cannot be reached or that ends before RPC's history begins; when none passes, the
  // first refusal is raised, else the first gap, else that none could be reached.
  async #first(): Promise<Loaded> {
    const { urls, vaults } = this.#o;
    if (urls.length === 0) {
      fail("history_unavailable", "RPC no longer holds the vault events this wallet needs", {
        reason: "archive_unconfigured",
      });
    }
    const views = await Promise.all(
      vaults.map((vault, i) =>
        i === 0
          ? vault.view()
          : vault.view().catch((err: unknown) => {
              if (err instanceof CyphrasError) return undefined;
              throw err;
            }),
      ),
    );
    let refused: CyphrasError | undefined;
    let gap: CyphrasError | undefined;
    for (const [i, url] of urls.entries()) {
      try {
        return await this.#from(url, views);
      } catch (err) {
        if (!(err instanceof CyphrasError)) throw err;
        if (err.code === "archive_fault") {
          refused ??= new CyphrasError(err.code, err.message, { ...err.details, archive: i });
        } else if (err.code === "history_unavailable" && reason(err) === "archive_gap") {
          gap ??= err;
        } else if (!(err.code === "history_unavailable" && reason(err) === "archive_unreachable")) {
          throw err;
        }
      }
    }
    throw (
      refused ??
      gap ??
      new CyphrasError("history_unavailable", "no copy of the vault's archive could be reached", {
        reason: "archive_unreachable",
      })
    );
  }

  async #from(url: string, views: readonly (ChainView | undefined)[]): Promise<Loaded> {
    const { fetch, pin, since, leafCount, rpcs } = this.#o;
    const manifest = await fetchManifest(fetch, url, pin);
    for (const view of views) if (view !== undefined) admits(manifest, view);
    const { windows } = manifest;
    const archiveEnd = windows[windows.length - 1]?.leaves[1] ?? 0;
    const leafNeed = windows.filter((w) => w.leaves[1] > Math.max(w.leaves[0], leafCount));
    const nfNeed = windows.filter((w) => w.nullifiers > 0 && w.end >= since);
    const leafTake = leafNeed.slice(0, this.#o.leafWindows);
    const nfTake = nfNeed.slice(0, this.#o.nullifierWindows);
    const leafCut = leafNeed.length > leafTake.length ? lastEnd(leafTake) : undefined;
    const nfCut = nfNeed.length > nfTake.length ? lastEnd(nfTake) : undefined;
    // Every leaf and spend of the ledgers up to the cut comes from the windows read.
    const cut = Math.min(leafCut ?? manifest.coveredTo, nfCut ?? manifest.coveredTo);
    const reads = windows.filter(
      (w) => w.start <= cut && (leafTake.includes(w) || nfTake.includes(w)),
    );
    const leaves: Leaf[] = [];
    const nullifiers: SpentNullifier[] = [];
    const spent = new Set<bigint>();
    for (const w of reads) {
      const content = await fetchWindow(fetch, url, w, pin);
      for (const n of content.nullifiers) {
        if (spent.has(n.nullifier)) fail("archive_fault", "the archive spends a nullifier twice");
        spent.add(n.nullifier);
        if (n.ledger >= since) nullifiers.push(n);
      }
      leaves.push(...content.leaves.filter((l) => l.index >= leafCount));
    }
    for (const [i, rpc] of rpcs.entries()) {
      if (views[i] !== undefined) await present(rpc, pin.vault, nullifiers);
    }
    const supplied = (leaves[leaves.length - 1]?.index ?? leafCount - 1) + 1;
    if (leafCut !== undefined) {
      return {
        leaves,
        nullifiers,
        completeTo: cut,
        part: { to: cut, end: supplied, tailFrom: undefined },
        tail: undefined,
      };
    }
    const tailFrom = Math.max(pin.deployLedger, manifest.coveredTo + 1);
    let tail: VaultEvents;
    try {
      tail = await new RpcEventSource(
        rpcs[0] as SorobanRpc,
        pin.vault,
        tailFrom,
        this.#o.eventPages,
      ).events();
    } catch (err) {
      if (err instanceof CyphrasError && err.code === "history_unavailable") {
        fail("history_unavailable", "RPC no longer holds the ledgers after the archive's last", {
          reason: "archive_gap",
          archiveTo: manifest.coveredTo,
        });
      }
      throw err;
    }
    // RPC's leaves after the archive's last ledger begin where the archive's end, one after another.
    if (tail.leaves.some((l, i) => l.index !== archiveEnd + i)) {
      fail("archive_fault", "the archive's leaves and RPC's events after it do not join");
    }
    const first = Math.max(leafCount, archiveEnd);
    return {
      leaves: [...leaves, ...tail.leaves.filter((l) => l.index >= first)],
      nullifiers:
        nfCut === undefined
          ? [...nullifiers, ...tail.nullifiers.filter((n) => n.ledger >= since)]
          : nullifiers,
      completeTo: nfCut ?? tail.latest,
      part: { to: cut, end: supplied, tailFrom },
      tail,
    };
  }

  async nextLeaves(_tree: CommitmentTree): Promise<LeafBatch> {
    return { leaves: (await this.#load()).leaves, done: true };
  }

  async nullifiers(_sinceLedger: number): Promise<NullifierSet> {
    const { nullifiers, completeTo } = await this.#load();
    return { nullifiers, completeToLedger: completeTo };
  }

  // RPC's events after the archive, when the sync read them.
  async events(): Promise<VaultEvents | undefined> {
    return (await this.#load()).tail;
  }

  async part(): Promise<ArchivePart> {
    return (await this.#load()).part;
  }
}

const lastEnd = (windows: readonly ArchiveWindow[]): number =>
  (windows[windows.length - 1] as ArchiveWindow).end;

// A manifest may not claim more than the vault has: more leaves than it holds, or ledgers past the
// one the provider read it at.
function admits(m: ArchiveManifest, view: ChainView): void {
  const leaves = m.windows[m.windows.length - 1]?.leaves[1] ?? 0;
  if (leaves > view.roots.nextLeaf) {
    fail("archive_fault", "the archive lists more leaves than the vault holds", {
      leaves,
      vaultLeaves: view.roots.nextLeaf,
    });
  }
  if (m.coveredTo > view.ledger) {
    fail("archive_fault", "the archive covers ledgers the chain has not closed", {
      coveredTo: m.coveredTo,
      latestLedger: view.ledger,
    });
  }
}

// Every nullifier must have an entry in the vault, live or archived, and each entry the RPC returns
// must be the one asked for. Only the public list of the archive is asked for, in the same batches
// by every wallet.
async function present(
  rpc: SorobanRpc,
  vault: string,
  nullifiers: readonly SpentNullifier[],
): Promise<void> {
  for (let i = 0; i < nullifiers.length; i += ENTRY_BATCH) {
    const batch = nullifiers.slice(i, i + ENTRY_BATCH);
    const keys = batch.map((n) => nullifierKey(vault, n.nullifier));
    const { entries } = await rpc.getLedgerEntries(keys);
    for (const key of keys) {
      const entry = entries.get(keyId(key));
      if (entry === undefined || ownKey(entry.data) !== keyId(key)) {
        fail("archive_fault", "the archive lists a nullifier the vault never spent");
      }
    }
  }
}

function ownKey(data: xdr.LedgerEntryData): string | undefined {
  if (data.switch().name !== "contractData") return undefined;
  const d = data.contractData();
  return keyId(
    xdr.LedgerKey.contractData(
      new xdr.LedgerKeyContractData({
        contract: d.contract(),
        key: d.key(),
        durability: d.durability(),
      }),
    ),
  );
}
