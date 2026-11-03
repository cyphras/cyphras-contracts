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
  // The ledger of the tree's last leaf, from which RPC's events carry on a tree staged past the
  // archive.
  readonly lastLeafLedger: number;
  // How many windows one sync reads at most, and the event pages of RPC.
  readonly windows: number;
  readonly eventPages: number;
  // Copies, by index, to pass over in this sync, and the nullifiers staged syncs took already.
  readonly skip?: readonly number[];
  readonly staged?: readonly bigint[];
  // The most the windows of one sync may hold decompressed, and the time the files of one copy
  // may take in one sync, in milliseconds of `now`.
  readonly byteBudget?: number;
  readonly deadlineMs?: number;
  readonly now?: () => number;
}

const ARCHIVE_BYTE_BUDGET = 256 << 20;
const ARCHIVE_DEADLINE_MS = 600_000;

interface Loaded {
  readonly leaves: readonly Leaf[];
  readonly nullifiers: readonly SpentNullifier[];
  readonly completeTo: number;
  readonly part: ArchivePart;
  readonly tail: VaultEvents | undefined;
  readonly copy: number;
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

  // Every copy's manifest is read first, and copies that list the same window must agree on it;
  // then the first copy that passes is taken. A copy that breaks a rule is passed over for the
  // next one, and so is one that cannot be reached or that ends before RPC's history begins; when
  // none passes, the first refusal is raised, else the first gap, else that none could be reached.
  async #first(): Promise<Loaded> {
    const { urls, vaults, fetch, pin } = this.#o;
    const skip = this.#o.skip ?? [];
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
    // Every copy has its own time, so a slow one cannot use up another's.
    const budget = this.#o.deadlineMs ?? ARCHIVE_DEADLINE_MS;
    let refused: CyphrasError | undefined;
    let gap: CyphrasError | undefined;
    const sort = (err: unknown, i: number): void => {
      if (!(err instanceof CyphrasError)) throw err;
      if (err.code === "archive_fault") {
        refused ??= new CyphrasError(err.code, err.message, { ...err.details, archive: i });
      } else if (
        err.code === "history_unavailable" &&
        ["archive_gap", "rpc_behind"].includes(`${reason(err)}`)
      ) {
        gap ??= err;
      } else if (!(err.code === "history_unavailable" && reason(err) === "archive_unreachable")) {
        throw err;
      }
    };
    const manifests: (ArchiveManifest | undefined)[] = [];
    for (const [i, url] of urls.entries()) {
      if (skip.includes(i)) continue;
      try {
        manifests[i] = await fetchManifest(fetch, url, pin, budget);
      } catch (err) {
        sort(err, i);
      }
    }
    agree(manifests);
    for (const [i, url] of urls.entries()) {
      const manifest = manifests[i];
      if (manifest === undefined) continue;
      try {
        return { ...(await this.#from(url, manifest, views, this.#now() + budget)), copy: i };
      } catch (err) {
        sort(err, i);
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

  #now(): number {
    return (this.#o.now ?? Date.now)();
  }

  // How long the next file may take: its own limit, within what is left of the sync's time for
  // the archive.
  #timeout(deadline: number): number {
    const left = deadline - this.#now();
    if (left <= 0) {
      fail("history_unavailable", "the vault's archive took too long to read", {
        reason: "archive_unreachable",
      });
    }
    return left;
  }

  async #from(
    url: string,
    manifest: ArchiveManifest,
    views: readonly (ChainView | undefined)[],
    deadline: number,
  ): Promise<Omit<Loaded, "copy">> {
    const { fetch, pin, since, leafCount, rpcs } = this.#o;
    admits(manifest, views);
    const { windows } = manifest;
    const archiveEnd = windows[windows.length - 1]?.leaves[1] ?? 0;
    // One cut for leaves and spends alike: the windows read are the first ones that hold either,
    // within the window cap and the byte budget, so everything up to the last one read is in.
    const need = windows.filter(
      (w) => w.leaves[1] > Math.max(w.leaves[0], leafCount) || (w.nullifiers > 0 && w.end >= since),
    );
    const budget = this.#o.byteBudget ?? ARCHIVE_BYTE_BUDGET;
    const take: ArchiveWindow[] = [];
    let bytes = 0;
    for (const w of need) {
      if (take.length === this.#o.windows || (take.length > 0 && bytes + w.bytes > budget)) break;
      take.push(w);
      bytes += w.bytes;
    }
    const cut = take.length < need.length ? lastEnd(take) : manifest.coveredTo;
    const leaves: Leaf[] = [];
    const nullifiers: SpentNullifier[] = [];
    // An honest archive spends a nullifier once, and never one a staged sync took already.
    const spent = new Set<bigint>(this.#o.staged ?? []);
    for (const w of take) {
      const content = await fetchWindow(fetch, url, w, pin, this.#timeout(deadline));
      const taken: SpentNullifier[] = [];
      for (const n of content.nullifiers) {
        if (spent.has(n.nullifier)) fail("archive_fault", "the archive spends a nullifier twice");
        spent.add(n.nullifier);
        if (n.ledger >= since) taken.push(n);
      }
      // A window of made-up nullifiers is refused before the next one is read.
      for (const [i, rpc] of rpcs.entries()) {
        if (views[i] !== undefined) await present(rpc, pin.vault, taken);
      }
      nullifiers.push(...taken);
      leaves.push(...content.leaves.filter((l) => l.index >= leafCount));
    }
    const supplied = (leaves[leaves.length - 1]?.index ?? leafCount - 1) + 1;
    if (cut < manifest.coveredTo) {
      return {
        leaves,
        nullifiers,
        completeTo: cut,
        part: { to: cut, end: supplied, tailFrom: undefined },
        tail: undefined,
      };
    }
    // RPC's events go on from the ledger after the archive's last, or, for a tree staged past the
    // archive, from where its spends and its last leaf left off.
    const after = Math.max(pin.deployLedger, manifest.coveredTo + 1);
    const tailFrom = Math.max(after, Math.min(since, this.#o.lastLeafLedger));
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
    // RPC's leaves follow one another, from where the archive's end when they start right after
    // it, or from no later than the tree's next leaf.
    const first = tail.leaves[0]?.index;
    if (
      first !== undefined &&
      (tail.leaves.some((l, i) => l.index !== first + i) ||
        (tailFrom === after ? first !== archiveEnd : first > Math.max(leafCount, archiveEnd)))
    ) {
      fail("archive_fault", "the archive's leaves and RPC's events after it do not join");
    }
    const next = Math.max(leafCount, archiveEnd);
    if (tail.nullifiers.some((n) => spent.has(n.nullifier))) {
      fail("archive_fault", "the archive spends a nullifier RPC's events after it spend");
    }
    // The archive and RPC's events after it must hold every leaf each provider shows the vault
    // has: a copy that leaves out its last pairs has a shorter tree whose root the ring still
    // holds. Each provider the tail reaches is asked; a tail that reaches none, as one stopped at
    // its page cap, cannot show it, and nothing is taken.
    const reached = views.filter((v): v is ChainView => v !== undefined && v.ledger <= tail.latest);
    if (reached.length === 0) {
      fail("history_unavailable", "RPC's events after the archive stop short of the vault", {
        reason: "rpc_tail_short",
      });
    }
    for (const view of reached) {
      const after = tail.leaves.filter((l) => l.index >= next && l.ledger <= view.ledger).length;
      if (next + after !== view.roots.nextLeaf) {
        fail(
          "archive_fault",
          "the archive and RPC's events after it hold fewer leaves than the vault",
          {
            leaves: next + after,
            vaultLeaves: view.roots.nextLeaf,
          },
        );
      }
    }
    return {
      leaves: [...leaves, ...tail.leaves.filter((l) => l.index >= next)],
      nullifiers: [...nullifiers, ...tail.nullifiers.filter((n) => n.ledger >= since)],
      completeTo: tail.latest,
      part: { to: cut, end: supplied, tailFrom },
      tail,
    };
  }

  // The copy the sync took its data from.
  async copy(): Promise<number> {
    return (await this.#load()).copy;
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
// one the provider read it at. A claim past every provider's view is the archive's lie; one past a
// provider that lags behind another is that provider's lag, and the sync waits for it.
function admits(m: ArchiveManifest, views: readonly (ChainView | undefined)[]): void {
  const answered = views.filter((v): v is ChainView => v !== undefined);
  const leaves = m.windows[m.windows.length - 1]?.leaves[1] ?? 0;
  const most = Math.max(...answered.map((v) => v.roots.nextLeaf));
  const latest = Math.max(...answered.map((v) => v.ledger));
  if (leaves > most) {
    fail("archive_fault", "the archive lists more leaves than the vault holds", {
      leaves,
      vaultLeaves: most,
    });
  }
  if (m.coveredTo > latest) {
    fail("archive_fault", "the archive covers ledgers the chain has not closed", {
      coveredTo: m.coveredTo,
      latestLedger: latest,
    });
  }
  if (answered.some((v) => leaves > v.roots.nextLeaf || m.coveredTo > v.ledger)) {
    fail("history_unavailable", "an RPC provider is behind the vault's archive", {
      reason: "rpc_behind",
    });
  }
}

// Copies that list the same window must hold the same one: what the chain cannot check of it, its
// ciphertexts and transactions, then rests on more than one copy.
function agree(manifests: readonly (ArchiveManifest | undefined)[]): void {
  const seen = new Map<number, { readonly key: string; readonly copy: number }>();
  manifests.forEach((m, copy) => {
    for (const w of m?.windows ?? []) {
      const key = JSON.stringify([w.sha256, w.events, w.leaves, w.nullifiers, w.bytes]);
      const other = seen.get(w.start);
      if (other === undefined) seen.set(w.start, { key, copy });
      else if (other.key !== key) {
        fail("archive_fault", "copies of the vault's archive disagree on a window", {
          copies: `${other.copy},${copy}`,
          window: w.start,
        });
      }
    }
  });
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
