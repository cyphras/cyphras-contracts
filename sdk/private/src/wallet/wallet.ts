import { expand, extract } from "@noble/hashes/hkdf";
import { sha512 } from "@noble/hashes/sha2";
import { scValToBigInt, xdr } from "@stellar/stellar-base";
import {
  decodeViewingKey,
  encodeAddress,
  encodeFullViewingKey,
  encodeIncomingViewingKey,
} from "../address.ts";
import { type ArtifactSource, PinnedArtifacts } from "../artifacts.ts";
import { packPoint } from "../babyjub.ts";
import { bigIntToBytesLE, concatBytes, randomBytes, utf8 } from "../bytes.ts";
import { CommitmentTree } from "../merkle.ts";
import { type Deployment, type DeploymentName, resolveDeployment } from "../deployments.ts";
import { CyphrasError, fail } from "../errors.ts";
import {
  type FullViewingKeys,
  type IncomingKeys,
  type SpendingKeys,
  addressKeyAt,
  addressKeyFor,
  defaultAddressKey,
  deriveSpendingKeys,
} from "../keys.ts";
import { type KeySource, checkSeed } from "../keysource.ts";
import type { FetchLike } from "../net/http.ts";
import type { IndexerClient } from "../net/indexer.ts";
import { RelayerClient } from "../net/relayer.ts";
import type { Prover } from "../prover.ts";
import { type AccountLock, lockName, soleInstance, webLock } from "../lock.ts";
import { type KeyValueStore, SealedStore } from "../storage.ts";
import type { ChainView } from "../vault/state.ts";
import {
  DEFAULT_NETWORK_FEE_CAPS,
  type NetworkFeeCaps,
  type TransactionSigner,
  invokeVault,
} from "../vault/invoke.ts";
import {
  type ChainReads,
  type Core,
  chainReads,
  claimRoom,
  invokeContext,
  newId,
  releaseRoom,
} from "./core.ts";
import {
  type DepositInfo,
  type ShieldReceipt,
  cancelDeposit,
  depositInfo,
  refundDeposit,
  shield,
  trackDeposits,
} from "./deposits.ts";
import {
  type DisclosureCheck,
  type PaymentDisclosure,
  disclose,
  verifyDisclosure,
} from "./disclosure.ts";
import { type ExitPosition, applyExits, exitPosition, payoutLeft, shownParts } from "./exits.ts";
import { type Balance, type HistoryEntry, balanceOf, historyOf } from "./history.ts";
import { updatePace } from "./pace.ts";
import { type Verification, createServices, verify } from "./services.ts";
import {
  DEFAULT_SYNC_LIMITS,
  IndexerSource,
  RpcEventSource,
  type SyncLimits,
  type VaultEvents,
} from "./sources.ts";
import {
  type ConfirmSpend,
  type Submission,
  cancelHeld,
  checkIssuer,
  followHeld,
  resendConflicted,
  spend,
  submissionOf,
} from "./spend.ts";
import {
  type ExitPart,
  LANDED_STATES,
  type Operation,
  type OwnedNote,
  type Plan,
  type RootCheck,
  StateStore,
  type UncheckedRange,
  type WalletState,
  emptyState,
} from "./state.ts";
import {
  type ScanKeys,
  advancePlans,
  applyDownload,
  checkRoot,
  crossCheck,
  downloadChain,
  eventsUpTo,
  isActive,
  landingProviders,
  recheck,
  recordEvents,
  resetEvidence,
  sameRecords,
  stageDownload,
} from "./sync.ts";

/** Options shared by full and view-only wallets. */
export interface ConnectionOptions {
  readonly deployment: DeploymentName | Deployment;
  // Accepts a Deployment object that this release does not pin, for tests and local vaults.
  readonly allowUnpinnedDeployment?: boolean;
  readonly storage: KeyValueStore;
  readonly rpcUrl: string;
  // A second RPC provider, read on every sync: a payment is declared dead only when both show it,
  // and a tree it contradicts is not taken. Recommended on mainnet.
  readonly secondRpcUrl?: string;
  // Every request goes through it, so the caller can route private-payment traffic via a proxy.
  readonly fetch?: FetchLike;
  // Service URLs other than the pinned ones; each must report the pinned vault and network.
  readonly indexers?: readonly string[];
  readonly relayers?: readonly string[];
  // The most a transaction the SDK builds may pay the network; defaults to 0.01 XLM for inclusion
  // and 1 XLM for resources.
  readonly networkFeeCaps?: Partial<NetworkFeeCaps>;
  // How much one sync downloads at most; the defaults suit an extension's service worker.
  readonly syncLimits?: Partial<SyncLimits>;
  // Starts from a fresh state when the stored one cannot be read, instead of refusing to open. The
  // first sync then rebuilds notes and history from the chain; local records of submissions and
  // deposits that were only in the lost state are gone, as stateReset() warns.
  readonly resetUnreadableState?: boolean;
  // Starts from a fresh state, in the same way, when the stored one is older than the last one
  // saved or missing while its record remains, as a restore from an old backup or a lost write
  // leaves it, instead of refusing to open with state_conflict.
  readonly resetRolledBackState?: boolean;
  // The caller's guarantee that no other wallet instance uses this store, needed where the
  // platform has no Web Locks API. Instances that share a store, such as an extension's popup and
  // its service worker, rely on Web Locks to run one operation at a time; without it two of them
  // could both spend a note.
  readonly singleInstance?: boolean;
  // For tests: the clock in milliseconds and the wait between polls.
  readonly clock?: () => number;
  readonly sleep?: (ms: number) => Promise<void>;
}

/** Options of PrivateWallet.open. */
export interface OpenOptions extends ConnectionOptions {
  readonly keys: KeySource;
  readonly prover: Prover;
  readonly artifacts: ArtifactSource;
}

/** Options of PrivateWallet.openViewOnly. */
export interface ViewOnlyOptions extends ConnectionOptions {
  readonly viewingKey: string;
}

/** What a sync found. */
export interface SyncSummary {
  readonly leafCount: number;
  // Leaves taken past leafCount that the vault has yet to confirm; the next sync continues.
  readonly staged: number;
  readonly newNotes: number;
  readonly source: "indexer" | "rpc";
  readonly rootVerified: boolean;
  // The new data matched the vault's events from every RPC provider other than the one it came
  // from, for the same ledgers.
  readonly crossChecked: boolean;
  // Ledgers whose spends, and leaves whose contents, not every RPC provider confirmed: later syncs
  // check them against the vault's events while the providers still hold them.
  readonly uncheckedLedgers: number;
  readonly uncheckedLeaves: number;
  // Of those leaves, the ones some RPC provider no longer holds while every other one confirmed
  // them: syncs ask every provider about them again each hour.
  readonly partialLeaves: number;
  // Of those leaves, the ones no RPC provider holds any more, so that nothing can check them: an
  // incoming payment an indexer hid among them stays hidden until a rescan through an indexer the
  // user trusts.
  readonly lostLeaves: number;
}

/** A shielded payment through a relayer. */
export interface SendRequest {
  readonly to: string;
  readonly amount: bigint;
  readonly maxFee: bigint;
  readonly relayer?: string | readonly string[];
  readonly confirm?: ConfirmSpend;
  // Unix seconds at most 24 hours ahead; the relayer submits at a random moment in the 10 minutes
  // after it.
  readonly notBefore?: number;
}

/** An unshield, relayed or, with selfRelay, submitted and paid for by the user's own account. */
export interface UnshieldRequest {
  readonly to: string;
  readonly amount: bigint;
  readonly maxFee?: bigint;
  readonly relayer?: string | readonly string[];
  readonly selfRelay?: TransactionSigner;
  readonly confirm?: ConfirmSpend;
  readonly notBefore?: number;
  // Splits an amount above the vault's single-exit cap into transactions spread over time.
  readonly split?: boolean;
  // Pays the asset's issuer, which burns the payout as a classic payment to it would. Refused
  // with destination_is_issuer unless set.
  readonly burnToIssuer?: boolean;
}

/** A stalled payment proved again, with the same notes. */
export interface RetryRequest {
  readonly maxFee?: bigint;
  readonly relayer?: string | readonly string[];
  readonly selfRelay?: TransactionSigner;
  readonly confirm?: ConfirmSpend;
}

/** A payment the SDK spreads over several transactions. */
export interface OperationView {
  readonly operationId: string;
  readonly total: bigint;
  readonly sent: bigint;
  readonly parts: number;
  readonly state: Operation["state"];
  // The part that blocks a blocked operation: it did not land, and its notes were spent elsewhere.
  // resumeOperation goes on without it, and abandonOperation stops the operation.
  readonly blockedBy: string | undefined;
  // Milliseconds since the epoch from which the next part may go.
  readonly nextAt: number;
  readonly plans: readonly Submission[];
}

/** A spend of this wallet. */
export interface PlanView extends Submission {
  readonly kind: Plan["kind"];
  readonly amount: bigint;
  readonly to: string;
  readonly createdAt: number;
  // The exit of an unshield that waits in the vault's exit queue: the ID transact gave it, what
  // it still owes the recipient, and the exits that owe it, a stranded one until claimed; and
  // whether that rests on the vault's events every RPC provider showed, rather than on the
  // indexer's account alone.
  readonly exitId: number | undefined;
  readonly payoutLeft: bigint | undefined;
  readonly exitParts: readonly ExitPart[];
  readonly exitConfirmed: boolean | undefined;
  readonly operationId: string | undefined;
  // The relayer's last word on a pending plan: held until its not_before, pending, success or
  // failed, or unknown when the relayer could not say. The chain's evidence alone confirms it.
  readonly relayerStatus: string | undefined;
  // The payment may still land, or failed by the wallet's last reading of the chain only: paying
  // it again must go through retry, which spends the same notes, never through a new send.
  readonly mustRetry: boolean;
  // Its deadline has passed, and the wallet cannot tell yet whether it landed, as it lacks part of
  // the vault's tree. The safe choice is retry: both spend the same notes, so at most one pays.
  readonly needsUserDecision: boolean;
}

/** Why the wallet opened on a fresh state in place of the stored one, and what was lost with it. */
export interface StateReset {
  readonly reason: "unreadable" | "rolled_back";
  readonly warning: string;
}

const STATE_RESET_WARNING =
  "The stored state was replaced by a fresh one, which the next sync rebuilds from the chain. " +
  "Records that only the lost state held are gone: a payment or split unshield in flight is no " +
  "longer followed and may still land, its notes look spendable until the chain shows them " +
  "spent, and a deposit being submitted is no longer tracked. Before paying again, wait until " +
  "any such payment has landed or its deadline has passed.";

const VIEWING_KEY_WARNING =
  "A viewing key reveals the whole history and future of this private account to whoever holds " +
  "it, and cannot be revoked. To prove a single payment, use disclosePayment instead.";

// Parts of a split unshield follow the previous part's landing by one to six hours, at random.
const SPLIT_GAP_MS = { min: 3_600_000, max: 21_600_000 };

function randomGap(): number {
  const r = new DataView(randomBytes(4).buffer).getUint32(0) / 2 ** 32;
  return SPLIT_GAP_MS.min + Math.floor(r * (SPLIT_GAP_MS.max - SPLIT_GAP_MS.min));
}

const leavesOf = (range: UncheckedRange): number =>
  range.leaves === undefined ? 0 : range.leaves.end - range.leaves.first;

// What became of the part an operation awaits. It landed, itself or as a retry by the same notes;
// it is dead with all its notes free, to go again with them; one of its notes was spent by a
// payment of this wallet that is no part of the operation and whose landing each of `providers`
// RPC providers confirmed, so the part can never land and never paid; or it did not land and its
// notes were spent elsewhere, which only the caller can judge.
function partFate(
  state: WalletState,
  parts: readonly Plan[],
  part: Plan,
  providers: number,
): "landed" | "again" | "unpaid" | "blocked" {
  const landed = (p: Plan): boolean => LANDED_STATES.includes(p.state);
  if (
    landed(part) ||
    parts.some((p) => landed(p) && p.nullifiers.some((nf) => part.nullifiers.includes(nf)))
  ) {
    return "landed";
  }
  const free = part.inputs.every((i) =>
    state.notes.some((n) => n.pos === i.pos && n.spent === undefined),
  );
  if (part.state === "dead" && free) return "again";
  const ours = state.plans.some(
    (q) =>
      !parts.includes(q) &&
      landingProviders(q) >= providers &&
      q.inputs.some((i) => part.inputs.some((input) => input.nf === i.nf)),
  );
  return ours ? "unpaid" : "blocked";
}

// A view-only wallet has no seed, so its store key comes from the viewing key: its state is as
// unreadable without that key as a full wallet's is without the seed.
function viewStoreKey(decoded: ReturnType<typeof decodeViewingKey>): Uint8Array {
  const keys: IncomingKeys = decoded.keys;
  const material =
    decoded.kind === "full"
      ? concatBytes(
          packPoint(decoded.keys.ak),
          packPoint(decoded.keys.nk),
          decoded.keys.ovk,
          decoded.keys.dk,
        )
      : concatBytes(keys.dk, bigIntToBytesLE(keys.ivk, 32));
  const prk = extract(sha512, material, utf8("cyphras/v2/view-store"));
  return expand(sha512, prk, utf8(`${keys.network}/${decoded.kind}`), 32);
}

const defaultFetch: FetchLike = (input, init) => globalThis.fetch(input, init);

/**
 * A private account on one vault. It syncs the pool, proves spends on this device and talks to
 * the vault's services; one operation runs at a time and the rest wait their turn.
 */
export class PrivateWallet {
  readonly #core: Core;
  readonly #fetch: FetchLike;
  readonly #states: StateStore;
  readonly #lock: AccountLock;
  readonly #limits: SyncLimits;
  #verification: Verification;
  readonly #reset: StateReset | undefined;
  #queue: Promise<unknown> = Promise.resolve();
  // The last sync found data that contradicts the chain; nothing of it was kept.
  #fault = false;

  private constructor(
    core: Core,
    fetchFn: FetchLike,
    states: StateStore,
    lock: AccountLock,
    limits: SyncLimits,
    verification: Verification,
    reset: StateReset | undefined,
  ) {
    this.#core = core;
    this.#fetch = fetchFn;
    this.#states = states;
    this.#lock = lock;
    this.#limits = limits;
    this.#verification = verification;
    this.#reset = reset;
  }

  /** Derives the keys, checks the pinned deployment and loads the local state. */
  static async open(options: OpenOptions): Promise<PrivateWallet> {
    const deployment = resolveDeployment(
      options.deployment,
      options.allowUnpinnedDeployment ?? false,
    );
    const material = await options.keys.resolve({
      network: deployment.network,
      storage: options.storage,
    });
    checkSeed(material);
    const keys = deriveSpendingKeys(material.seed, deployment.network, material.account);
    material.seed.fill(0);
    const scan: ScanKeys = {
      network: deployment.network,
      incoming: keys,
      ovk: keys.ovk,
      nkFold: keys.nkFold,
    };
    return PrivateWallet.#start(
      options,
      deployment,
      scan,
      keys,
      keys.storeKey,
      options.prover,
      new PinnedArtifacts(options.artifacts, deployment.artifacts),
    );
  }

  /** A wallet that syncs and reports from an incoming or full viewing key and cannot spend. */
  static async openViewOnly(options: ViewOnlyOptions): Promise<PrivateWallet> {
    const deployment = resolveDeployment(
      options.deployment,
      options.allowUnpinnedDeployment ?? false,
    );
    const decoded = decodeViewingKey(deployment.network, options.viewingKey);
    const full = decoded.kind === "full" ? decoded.keys : undefined;
    const scan: ScanKeys = {
      network: deployment.network,
      incoming: decoded.keys,
      ovk: full?.ovk,
      nkFold: full?.nkFold,
    };
    return PrivateWallet.#start(
      options,
      deployment,
      scan,
      undefined,
      viewStoreKey(decoded),
      undefined,
      undefined,
    );
  }

  static async #start(
    options: ConnectionOptions,
    deployment: Deployment,
    scan: ScanKeys,
    keys: SpendingKeys | undefined,
    storeKey: Uint8Array,
    prover: Prover | undefined,
    artifacts: PinnedArtifacts | undefined,
  ): Promise<PrivateWallet> {
    const fetchFn = options.fetch ?? defaultFetch;
    const services = createServices(
      deployment,
      options.rpcUrl,
      fetchFn,
      options.indexers,
      options.relayers,
      options.secondRpcUrl,
    );
    const store = new SealedStore(options.storage, storeKey);
    const states = new StateStore(store);
    let state: WalletState;
    let reset: StateReset | undefined;
    try {
      state = (await states.load()) ?? emptyState(deployment.deployLedger);
    } catch (err) {
      const code = err instanceof CyphrasError ? err.code : undefined;
      const reason =
        code === "storage_unreadable" && options.resetUnreadableState === true
          ? "unreadable"
          : code === "state_conflict" && options.resetRolledBackState === true
            ? "rolled_back"
            : undefined;
      if (reason === undefined) throw err;
      await states.discard();
      state = emptyState(deployment.deployLedger);
      reset = { reason, warning: STATE_RESET_WARNING };
    }
    const now = options.clock ?? (() => Date.now());
    const sleep =
      options.sleep ?? ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)));
    const lock =
      webLock(lockName(storeKey)) ??
      (options.singleInstance === true
        ? soleInstance
        : fail(
            "locks_unavailable",
            "this platform has no Web Locks API; set singleInstance if only one wallet instance uses this store",
          ));
    const core: Core = {
      deployment,
      services,
      scan,
      keys,
      self: defaultAddressKey(scan.incoming),
      prover,
      artifacts,
      state,
      chain: undefined,
      feeCaps: { ...DEFAULT_NETWORK_FEE_CAPS, ...options.networkFeeCaps },
      save: () => states.save(state),
      now,
      sleep,
    };
    const { verification } = await verify(services);
    const limits = { ...DEFAULT_SYNC_LIMITS, ...options.syncLimits };
    return new PrivateWallet(core, fetchFn, states, lock, limits, verification, reset);
  }

  /**
   * Checks a payment disclosure against the chain without keys, from the transaction's events in
   * RPC. Once RPC no longer holds the transaction, the check succeeds on the indexer's word only
   * with acceptIndexerOnly, and says so in confirmedBy.
   */
  static async verifyDisclosure(
    doc: unknown,
    options: Pick<
      ConnectionOptions,
      "deployment" | "allowUnpinnedDeployment" | "rpcUrl" | "fetch" | "indexers"
    > & { readonly acceptIndexerOnly?: boolean },
  ): Promise<DisclosureCheck> {
    const deployment = resolveDeployment(
      options.deployment,
      options.allowUnpinnedDeployment ?? false,
    );
    const services = createServices(
      deployment,
      options.rpcUrl,
      options.fetch ?? defaultFetch,
      options.indexers,
      [],
      undefined,
    );
    return verifyDisclosure(
      doc,
      deployment.network,
      deployment.vault,
      services.indexers[0],
      services.rpc,
      options.acceptIndexerOnly ?? false,
    );
  }

  // Runs one operation at a time: in this instance through its queue, and across the instances
  // that share the store through the account lock. Each starts from the latest saved state.
  #run<T>(task: () => Promise<T>): Promise<T> {
    const locked = (): Promise<T> =>
      this.#lock.hold(async () => {
        const latest = await this.#states.load();
        if (latest !== undefined && latest.revision !== this.#core.state.revision) {
          Object.assign(this.#core.state, latest);
        }
        return task();
      });
    const next = this.#queue.then(locked, locked);
    this.#queue = next.catch(() => undefined);
    return next;
  }

  get network(): Deployment["network"] {
    return this.#core.deployment.network;
  }

  get deploymentId(): string {
    return this.#core.deployment.id;
  }

  get viewOnly(): boolean {
    return this.#core.keys === undefined;
  }

  /** What the checks of the pinned deployment found; shields and spends need "verified". */
  verification(): Verification {
    return this.#verification;
  }

  /** Set when opening replaced the stored state with a fresh one, with a warning to show the user. */
  stateReset(): StateReset | undefined {
    return this.#reset;
  }

  /** The local tree's size and whether its root was last found in the vault's history. */
  treeStatus(): {
    readonly leafCount: number;
    readonly verified: boolean;
    readonly fault: boolean;
  } {
    const { state } = this.#core;
    return {
      leafCount: state.tree.leafCount,
      verified: state.rootCheck?.state === "verified",
      fault: this.#fault,
    };
  }

  async #ensureVerified(): Promise<void> {
    if (this.#verification.state === "unverified") {
      this.#verification = (await verify(this.#core.services)).verification;
    }
    if (this.#verification.state === "mismatch") {
      fail("deployment_mismatch", this.#verification.reason ?? "a service points elsewhere");
    }
    if (this.#verification.state !== "verified") {
      fail("service_unavailable", "the RPC or the vault could not be checked", { service: "rpc" });
    }
  }

  /** The cy1 or cyt1 address at a diversifier index, or the default address. */
  generateAddress(index?: number): string {
    const { scan, self } = this.#core;
    if (index === undefined) return encodeAddress(scan.network, self.d, self.pkd);
    if (!Number.isInteger(index) || index < 0 || index > 0xffffffff) {
      fail("invalid_argument", "a diversifier index is a 32-bit integer");
    }
    const key = addressKeyAt(scan.incoming, index);
    if (key === undefined) fail("invalid_argument", "this diversifier index has no valid address");
    return encodeAddress(scan.network, key.d, key.pkd);
  }

  #indexer(): IndexerClient | undefined {
    const ready = this.#verification.indexers.find((i) => i.state === "ok");
    return this.#core.services.indexers.find((i) => i.url === ready?.url);
  }

  #rpcSource(core: Core): RpcEventSource {
    const { state, deployment, services } = core;
    const lastLeaf = state.staging?.lastLeafLedger ?? state.lastLeafLedger;
    const from = Math.min(state.nullifierSince, lastLeaf || state.nullifierSince);
    return new RpcEventSource(
      services.rpc,
      deployment.vault,
      Math.max(deployment.deployLedger, from),
      this.#limits.eventPages,
    );
  }

  // A sync works on a copy of the state and keeps it only when every check passed, so data that
  // contradicts the chain never reaches the store, nor survives into a later sync.
  async #sync(full: boolean): Promise<SyncSummary> {
    await this.#ensureVerified();
    const core = this.#core;
    const draft = structuredClone(core.state);
    if (full) {
      const { revision, plans, deposits, operations } = draft;
      resetEvidence(plans);
      Object.assign(draft, emptyState(core.deployment.deployLedger), {
        revision,
        plans,
        deposits,
        operations,
      });
    }
    let summary: SyncSummary;
    try {
      summary = await this.#syncInto({ ...core, state: draft, save: async () => {} }, (reads) => {
        core.chain = reads;
      });
    } catch (err) {
      this.#fault =
        err instanceof CyphrasError &&
        (err.code === "indexer_fault" || err.code === "tree_unverified");
      // Staged leaves were never confirmed and may be what contradicts the vault; the next sync
      // takes them again from the confirmed tree.
      if (this.#fault && core.state.staging !== undefined) {
        core.state.staging = undefined;
        await core.save();
      }
      throw err;
    }
    this.#fault = false;
    Object.assign(core.state, draft);
    await core.save();
    return summary;
  }

  async #syncInto(core: Core, onReads: (reads: ChainReads) => void): Promise<SyncSummary> {
    const indexer = this.#indexer();
    const limits = this.#limits;
    let source: IndexerSource | RpcEventSource =
      indexer === undefined
        ? this.#rpcSource(core)
        : new IndexerSource(indexer, limits.nullifierPages);
    const second = core.services.second;
    const vaults =
      second === undefined ? [core.services.vault] : [core.services.vault, second.vault];
    let download;
    try {
      download = await downloadChain(core.state, source, vaults, limits.leafPages);
    } catch (err) {
      // An indexer that becomes unreachable is passed over for the vault's RPC events; one that
      // served inconsistent data is a fault the caller must see.
      if (
        !(err instanceof CyphrasError) ||
        source.kind === "rpc" ||
        err.code !== "service_unavailable"
      ) {
        throw err;
      }
      source = this.#rpcSource(core);
      download = await downloadChain(core.state, source, vaults, limits.leafPages);
    }
    const { views, data } = download;
    const view = views[0] as ChainView;
    const vault = core.deployment.vault;
    const rpcs = second === undefined ? [core.services.rpc] : [core.services.rpc, second.rpc];
    // The new data matched the vault's events from every RPC provider other than its source.
    let crossChecked: boolean;
    // The new data counts as the vault's own: cross-checked, or from the only RPC provider.
    let checked: boolean;
    // The vault's own events, from the first RPC provider, for the ledgers of this sync, when it
    // held them, and the other providers' for the same ledgers.
    let events: VaultEvents | undefined;
    let others: VaultEvents[];
    if (source.kind === "indexer") {
      const matches = [];
      for (const rpc of rpcs) matches.push(await crossCheck(rpc, vault, data, limits.eventPages));
      const heads = matches.flatMap((m) => (m.events === undefined ? [] : [m.events.head]));
      if (heads.length > 0 && data.completeTo > Math.max(data.horizon, ...heads)) {
        fail("indexer_fault", "the indexer claims to be complete past the chain's latest ledger");
      }
      crossChecked = matches.every((m) => m.verified);
      checked = crossChecked;
      events = matches[0]?.events;
      others = matches.slice(1).flatMap((m) => (m.events === undefined ? [] : [m.events]));
    } else {
      events = await source.events();
      const match =
        second === undefined
          ? undefined
          : await crossCheck(second.rpc, vault, data, limits.eventPages);
      crossChecked = match?.verified === true;
      checked = second === undefined || crossChecked;
      others = match?.events === undefined ? [] : [match.events];
    }
    // The vault's exits and deposits of this sync's ledgers count only where its data counts as
    // the vault's own, and every provider shows them alike.
    const shown = checked ? events : undefined;
    if (shown !== undefined) sameRecords([shown, ...others], data.since, data.horizon);
    const checks = views.map((v) => (v === undefined ? undefined : checkRoot(data.tree, v.roots)));
    if (checks.some((c) => c?.state === "mismatch")) {
      fail(
        "tree_unverified",
        "the synced tree contradicts the vault; nothing of this sync was kept",
      );
    }
    const check = checks[0] as RootCheck;
    // Only leaves under a root every RPC provider confirms count: notes at them, spends of notes and
    // where payments landed. While a provider is behind or cannot answer, they wait in staging, and
    // no payment's fate moves.
    const verified = checks.every((c) => c?.state === "verified");
    let newNotes = 0;
    if (verified) {
      newNotes = applyDownload(core.state, core.scan, data, checked, views.length);
      core.state.rootCheck = check;
      // RPC's events count towards a plan's fate only where every provider's matched the data.
      if (crossChecked && events !== undefined) {
        recordEvents(core.state.plans, eventsUpTo(events, data.horizon));
      }
    } else {
      stageDownload(core.state, core.scan, data, checked);
      core.state.rootCheck = checkRoot(CommitmentTree.fromSnapshot(core.state.tree), view.roots);
    }
    const rechecked = await recheck(core.state, rpcs, vault, limits.eventPages, core.now());
    if (rechecked !== undefined) recordEvents(core.state.plans, rechecked);
    if (verified) advancePlans(core.state, views as [ChainView, ...ChainView[]]);
    const live = source.kind === "indexer" ? indexer : undefined;
    const pace = updatePace(core.state, events?.times ?? []);
    // Read on every sync, so that an unshield, whose warnings use it, adds no request of its own.
    onReads({ view, stats: await live?.stats().catch(() => undefined), pace });
    const within = <T extends { readonly ledger: number }>(xs: readonly T[]): T[] =>
      xs.filter((x) => x.ledger >= data.since && x.ledger <= data.horizon);
    // What a recheck cleared is older than this sync's ledgers, and goes first.
    await trackDeposits(core, await live?.deposits().catch(() => undefined), [
      ...(rechecked?.deposits ?? []),
      ...within(shown?.deposits ?? []),
    ]);
    applyExits(
      core.state,
      [
        ...(rechecked === undefined
          ? []
          : [{ from: rechecked.from, to: rechecked.latest, events: rechecked.exits }]),
        ...(shown === undefined
          ? []
          : [{ from: data.since, to: data.horizon, events: within(shown.exits) }]),
      ],
      await live?.exits().catch(() => undefined),
      view.ledger,
    );
    await this.#pollRelayers(core, view.ledger, pace);
    return {
      leafCount: core.state.tree.leafCount,
      staged:
        (core.state.staging?.tree.leafCount ?? core.state.tree.leafCount) -
        core.state.tree.leafCount,
      newNotes,
      source: source.kind,
      rootVerified: core.state.rootCheck.state === "verified",
      crossChecked,
      uncheckedLedgers: core.state.unchecked.reduce(
        (n, r) => n + Math.max(0, r.to - r.from + 1),
        0,
      ),
      uncheckedLeaves: core.state.unchecked.reduce((n, r) => n + leavesOf(r), 0),
      partialLeaves: core.state.unchecked.reduce(
        (n, r) => n + (r.status === "partial" ? leavesOf(r) : 0),
        0,
      ),
      lostLeaves: core.state.unchecked.reduce(
        (n, r) => n + (r.status === "lost" ? leavesOf(r) : 0),
        0,
      ),
    };
  }

  // Asks only the relayer that took each pending plan about it: by its transaction's hash, or by
  // the ID of a request the relayer holds until its not_before.
  async #pollRelayers(core: Core, latest: number, pace: number): Promise<void> {
    for (const plan of core.state.plans) {
      const route = plan.route;
      if (plan.state !== "submitted" || route.kind !== "relayer") continue;
      const client = this.#relayerClients(route.url)[0] as RelayerClient;
      const { txHash, heldId } = plan;
      if (txHash !== undefined) {
        const tx = await client.tx(txHash).catch(() => undefined);
        plan.relayerStatus = tx?.status ?? "unknown";
        if (tx?.status === "failed" && tx.code === "unavailable") {
          await resendConflicted(plan, client, latest).catch(() => {
            plan.relayerStatus = "unknown";
          });
        }
      } else if (heldId !== undefined) {
        await followHeld(core, plan, heldId, client, latest, pace).catch(() => {
          plan.relayerStatus = "unknown";
        });
      }
    }
  }

  /** Fetches new leaves, nullifiers and the entry queue, scans them and updates the tree. */
  sync(): Promise<SyncSummary> {
    return this.#run(() => this.#sync(false));
  }

  /** A full rescan: cached spent flags are dropped and rebuilt from the nullifier set. */
  rescan(): Promise<SyncSummary> {
    return this.#run(() => this.#sync(true));
  }

  /** Spendable value, value in pending deposits and value locked in unconfirmed submissions. */
  async balance(): Promise<Balance> {
    return balanceOf(this.#core.state, this.#core.scan.nkFold !== undefined);
  }

  /** Shields, refunds, cancellations, received and sent payments, and unshields. */
  async history(): Promise<HistoryEntry[]> {
    return historyOf(this.#core.state);
  }

  /** This wallet's deposits and where each stands in the entry queue. */
  async deposits(): Promise<DepositInfo[]> {
    return this.#core.state.deposits.map(depositInfo);
  }

  /** This wallet's spends and their states in the submission state machine. */
  async plans(): Promise<PlanView[]> {
    return this.#core.state.plans.map((p) => ({
      ...submissionOf(p),
      kind: p.kind,
      amount: p.amount,
      to: p.to,
      createdAt: p.createdAt,
      exitId: p.exit?.id,
      payoutLeft: p.exit === undefined ? undefined : payoutLeft(p.exit),
      exitParts: (p.exit === undefined ? [] : shownParts(p.exit)).map((part) => ({ ...part })),
      exitConfirmed:
        p.exit === undefined ? undefined : p.exit.confirmed && p.exit.account === undefined,
      operationId: p.operationId,
      relayerStatus: p.relayerStatus,
      mustRetry: isActive(p) || p.state === "dead",
      needsUserDecision: isActive(p) && (this.#core.state.rootCheck?.ledger ?? 0) >= p.deadline,
    }));
  }

  /** Proves a deposit, has the depositor sign it, submits it and returns its deposit ID. */
  shield(request: {
    readonly amount: bigint;
    readonly signer: TransactionSigner;
  }): Promise<ShieldReceipt> {
    return this.#run(async () => {
      await this.#ensureVerified();
      return shield(this.#core, request.amount, request.signer);
    });
  }

  /** Cancels a deposit that is not yet admitted; the signer must be its depositor. */
  cancelDeposit(id: number, signer: TransactionSigner): Promise<{ readonly txHash: string }> {
    return this.#run(async () => {
      await this.#ensureVerified();
      return { txHash: await cancelDeposit(this.#core, id, signer) };
    });
  }

  /** Claims the refund of a flagged deposit; any account can submit it, the funds go to the depositor. */
  refundDeposit(id: number, signer: TransactionSigner): Promise<{ readonly txHash: string }> {
    return this.#run(async () => {
      await this.#ensureVerified();
      return { txHash: await refundDeposit(this.#core, id, signer) };
    });
  }

  #relayerClients(choice: string | readonly string[] | undefined): RelayerClient[] {
    const { services } = this.#core;
    if (choice === undefined) return services.relayers.map((r) => r.client);
    const urls = typeof choice === "string" ? [choice] : choice;
    return urls.map(
      (url) =>
        services.relayers.find((r) => r.client.url === url)?.client ??
        new RelayerClient(url, this.#fetch),
    );
  }

  /** Pays a shielded address through a relayer. */
  send(request: SendRequest): Promise<Submission> {
    return this.#run(async () => {
      await this.#sync(false);
      return spend(this.#core, {
        kind: "send",
        to: request.to,
        amount: request.amount,
        maxFee: request.maxFee,
        relayers: this.#relayerClients(request.relayer),
        selfRelay: undefined,
        confirm: request.confirm,
        notBefore: request.notBefore,
        inputs: undefined,
        retryOf: undefined,
        operationId: undefined,
        parts: 1,
        burnToIssuer: false,
        onPlan: undefined,
      });
    });
  }

  /**
   * Pays a Stellar address through a relayer or, with selfRelay, from the user's own account.
   * With split, an amount above the vault's single-exit cap becomes an operation whose parts go
   * one after another; continueOperations sends each next part once it is due.
   */
  unshield(request: UnshieldRequest): Promise<Submission | OperationView> {
    return this.#run(async () => {
      await this.#sync(false);
      const maxFee = request.selfRelay === undefined ? request.maxFee : 0n;
      if (maxFee === undefined) fail("invalid_argument", "a relayed unshield needs maxFee");
      const { limits } = chainReads(this.#core).view.instance;
      const burnToIssuer = request.burnToIssuer === true;
      if (request.split === true && request.amount + maxFee > limits.maxDailyOutflow) {
        checkIssuer(this.#core.deployment.asset.name, request.to, burnToIssuer);
        return this.#startSplit(request, maxFee, limits.maxDailyOutflow - maxFee);
      }
      return spend(this.#core, {
        kind: "unshield",
        to: request.to,
        amount: request.amount,
        maxFee,
        relayers: request.selfRelay === undefined ? this.#relayerClients(request.relayer) : [],
        selfRelay: request.selfRelay,
        confirm: request.confirm,
        notBefore: request.notBefore,
        inputs: undefined,
        retryOf: undefined,
        operationId: undefined,
        parts: 1,
        burnToIssuer,
        onPlan: undefined,
      });
    });
  }

  async #startSplit(
    request: UnshieldRequest,
    maxFee: bigint,
    partSize: bigint,
  ): Promise<OperationView> {
    if (partSize <= 0n) fail("limit_exceeded", "the fee cap leaves no room for a payout");
    const parts = Number((request.amount + partSize - 1n) / partSize);
    // The whole operation is confirmed once; each part still raises its own warnings.
    const confirmed =
      request.confirm !== undefined &&
      (await request.confirm({
        kind: "unshield",
        amount: request.amount,
        fee: maxFee * BigInt(parts),
        to: request.to,
        relayer: undefined,
        warnings: [],
        parts,
      }));
    if (!confirmed) fail("not_confirmed", "a split unshield must be confirmed as a whole");
    const op: Operation = {
      id: newId(),
      kind: "split_unshield",
      to: request.to,
      total: request.amount,
      partSize,
      maxFee,
      route:
        request.selfRelay === undefined
          ? { kind: "relayers", urls: this.#relayerClients(request.relayer).map((r) => r.url) }
          : { kind: "self", account: request.selfRelay.publicKey },
      awaiting: undefined,
      nextAt: this.#core.now(),
      state: "active",
      blockedBy: undefined,
    };
    this.#core.state.operations.push(op);
    await this.#core.save();
    await this.#nextPart(op, request.selfRelay, undefined, undefined, request.confirm);
    return this.#operationView(op);
  }

  #sent(op: Operation): bigint {
    return this.#core.state.plans
      .filter((p) => p.operationId === op.id && LANDED_STATES.includes(p.state))
      .reduce((s, p) => s + p.amount, 0n);
  }

  // Sends the next part of an operation, or a dead one again with its own notes.
  async #nextPart(
    op: Operation,
    signer: TransactionSigner | undefined,
    inputs: OwnedNote[] | undefined,
    again: Plan | undefined,
    confirm?: ConfirmSpend,
  ): Promise<void> {
    const remaining = op.total - this.#sent(op);
    await spend(this.#core, {
      kind: "unshield",
      to: op.to,
      amount: again?.amount ?? (remaining < op.partSize ? remaining : op.partSize),
      maxFee: op.maxFee,
      relayers: op.route.kind === "relayers" ? this.#relayerClients(op.route.urls) : [],
      selfRelay: signer,
      // Later parts were confirmed with the whole operation; their warnings cannot stop them.
      confirm: confirm ?? (() => true),
      notBefore: undefined,
      inputs,
      retryOf: again?.id,
      operationId: op.id,
      parts: Number((op.total + op.partSize - 1n) / op.partSize),
      // The operation was agreed to as a whole, its destination included.
      burnToIssuer: true,
      // The operation follows the part from the moment it is saved, whatever then becomes of its
      // submission, and sends nothing more until its fate is known.
      onPlan: (plan) => {
        op.awaiting = plan.id;
      },
    });
  }

  #operationView(op: Operation): OperationView {
    return {
      operationId: op.id,
      total: op.total,
      sent: this.#sent(op),
      parts: Number((op.total + op.partSize - 1n) / op.partSize),
      state: op.state,
      blockedBy: op.blockedBy,
      nextAt: op.nextAt,
      plans: this.#core.state.plans.filter((p) => p.operationId === op.id).map(submissionOf),
    };
  }

  // One step of an operation: follows the part it awaits, then sends the next one once it is due.
  // With `resume`, a part that blocks the operation is taken, on the caller's word, for one that
  // never paid.
  async #advance(
    op: Operation,
    signer: TransactionSigner | undefined,
    resume: boolean,
  ): Promise<void> {
    if (op.state === "done" || op.state === "abandoned") return;
    const { state } = this.#core;
    const parts = state.plans.filter((p) => p.operationId === op.id);
    if (parts.some(isActive)) return;
    // A self-relayed part goes only with its signer; the operation's state moves without it.
    const sends = op.route.kind !== "self" || signer?.publicKey === op.route.account;
    const relay = op.route.kind === "self" ? signer : undefined;
    const awaiting = parts.find((p) => p.id === op.awaiting);
    if (awaiting !== undefined) {
      const providers = this.#core.services.second === undefined ? 1 : 2;
      const fate = partFate(state, parts, awaiting, providers);
      if (fate === "blocked" && !resume) {
        op.state = "blocked";
        op.blockedBy = awaiting.id;
        return;
      }
      op.state = "active";
      op.blockedBy = undefined;
      if (fate === "again") {
        const notes = awaiting.inputs.map(
          (i) => state.notes.find((n) => n.pos === i.pos) as OwnedNote,
        );
        if (sends) await this.#nextPart(op, relay, notes, awaiting);
        return;
      }
      op.awaiting = undefined;
      // A part that never paid takes no gap: the next one goes in its place.
      if (fate === "landed") op.nextAt = this.#core.now() + randomGap();
    }
    if (this.#sent(op) >= op.total) {
      op.state = "done";
      return;
    }
    if (this.#core.now() < op.nextAt || !sends) return;
    await this.#nextPart(op, relay, undefined, undefined);
  }

  #operation(operationId: string): Operation {
    const op = this.#core.state.operations.find((o) => o.id === operationId);
    if (op === undefined) fail("not_found", "no operation has that ID");
    return op;
  }

  /**
   * Sends the next part of each split unshield whose previous part has landed and whose random
   * gap has passed. A part that is dead goes again with its own notes, as retry sends it. A part
   * whose notes a landed payment of this wallet spent never paid, and the next part takes its
   * place. One that did not land and whose notes were spent elsewhere blocks the operation until
   * it lands after all, or the caller resumes or abandons the operation. A self-relayed operation
   * needs its signer again.
   */
  continueOperations(signer?: TransactionSigner): Promise<OperationView[]> {
    return this.#run(async () => {
      await this.#sync(false);
      for (const op of this.#core.state.operations) await this.#advance(op, signer, false);
      await this.#core.save();
      return this.#core.state.operations.map((op) => this.#operationView(op));
    });
  }

  /**
   * Goes on with a blocked split unshield on the caller's word that the part blocking it never
   * paid, as when its notes were spent elsewhere: the next part goes in its place, with other
   * notes. Should the part have landed after all, the operation simply goes on from it.
   */
  resumeOperation(operationId: string, signer?: TransactionSigner): Promise<OperationView> {
    return this.#run(async () => {
      await this.#sync(false);
      const op = this.#operation(operationId);
      if (op.state !== "blocked") fail("invalid_argument", "only a blocked operation resumes");
      await this.#advance(op, signer, true);
      await this.#core.save();
      return this.#operationView(op);
    });
  }

  /**
   * Stops a split unshield that is not done: nothing more of it is sent. Parts already sent are
   * followed as before, and count as sent once they land.
   */
  abandonOperation(operationId: string): Promise<OperationView> {
    return this.#run(async () => {
      const op = this.#operation(operationId);
      if (op.state === "done") fail("invalid_argument", "the operation is done");
      op.state = "abandoned";
      await this.#core.save();
      return this.#operationView(op);
    });
  }

  /**
   * Proves a stalled or dead payment again with the same notes, so at most one of the two can
   * land. The relayer, the fee cap and self-relay may differ from the first attempt.
   */
  retry(planId: string, request: RetryRequest): Promise<Submission> {
    return this.#run(async () => {
      await this.#sync(false);
      const { state } = this.#core;
      const plan = state.plans.find((p) => p.id === planId);
      if (plan === undefined) fail("not_found", "no plan has that ID");
      if (!isActive(plan) && plan.state !== "dead") {
        fail("invalid_argument", "only a prepared, submitted or dead plan can be retried");
      }
      const inputs = plan.inputs.map((input) => {
        const note = state.notes.find((n) => n.pos === input.pos);
        if (note === undefined || note.spent !== undefined) {
          return fail("invalid_argument", "a note of the plan has been spent");
        }
        return note;
      });
      return spend(this.#core, {
        kind: plan.kind,
        to: plan.to,
        amount: plan.amount,
        maxFee: request.selfRelay === undefined ? (request.maxFee ?? plan.fee) : 0n,
        relayers: request.selfRelay === undefined ? this.#relayerClients(request.relayer) : [],
        selfRelay: request.selfRelay,
        confirm: request.confirm,
        notBefore: undefined,
        inputs,
        retryOf: plan.id,
        operationId: plan.operationId,
        parts: 1,
        // The plan's destination was agreed to when it was made.
        burnToIssuer: true,
        onPlan: undefined,
      });
    });
  }

  /**
   * Asks the relayer that holds a payment until its notBefore not to send it. True once the
   * relayer confirms it will not, false when it no longer holds the payment, as when it has sent
   * it already; either way the wallet does not send it again. The payment keeps its notes until
   * the chain shows that it cannot land, since the relayer has seen its proof.
   */
  cancelHeld(planId: string): Promise<boolean> {
    return this.#run(async () => {
      const plan = this.#core.state.plans.find((p) => p.id === planId);
      if (plan === undefined) fail("not_found", "no plan has that ID");
      const { heldId, route } = plan;
      if (plan.state !== "submitted" || heldId === undefined || route.kind !== "relayer") {
        fail("invalid_argument", "only a payment a relayer holds can be cancelled");
      }
      const cancelled = await cancelHeld(
        plan,
        heldId,
        this.#relayerClients(route.url)[0] as RelayerClient,
      );
      await this.#core.save();
      return cancelled;
    });
  }

  /** Where a queued payout of this wallet stands in the vault's exit queue, and when it is due. */
  async exitPosition(planId: string): Promise<ExitPosition | undefined> {
    const plan = this.#core.state.plans.find((p) => p.id === planId);
    const exit = plan?.exit;
    const queued = exit?.parts.find((p) => !p.stranded && p.payoutLeft > 0n);
    if (plan === undefined || exit === undefined || queued === undefined) return undefined;
    const queue = await this.#indexer()?.exits();
    if (queue === undefined) return undefined;
    // Until a first part is paid, the recipient's account does not exist.
    return exitPosition(queue, queued.id, plan.createsAccount && payoutLeft(exit) === plan.amount);
  }

  /**
   * Pays queued exits in FIFO order, up to `max`, as far as today's outflow window reaches; anyone
   * may call it. While the vault cannot pay out, it stops with the queue as it is, and fails with
   * the vault error VaultCannotPay when it could pay nothing.
   */
  releaseExits(signer: TransactionSigner, max = 10): Promise<{ readonly txHash: string }> {
    return this.#run(async () => {
      await this.#ensureVerified();
      const { hash } = await invokeVault(invokeContext(this.#core), signer, {
        fn: "release",
        args: [xdr.ScVal.scvU32(max)],
        transfers: [],
        extend: releaseRoom(this.#core, max),
      });
      return { txHash: hash };
    });
  }

  /**
   * Moves the parts of a stranded exit whose recipient or relayer can receive again back to the
   * tail of the exit queue, as the exit it returns; release then pays it. Anyone may submit it.
   */
  claimExit(
    exitId: number,
    signer: TransactionSigner,
  ): Promise<{ readonly txHash: string; readonly requeuedAs: number }> {
    return this.#run(async () => {
      await this.#ensureVerified();
      const { hash, returnValue } = await invokeVault(invokeContext(this.#core), signer, {
        fn: "claim",
        args: [xdr.ScVal.scvU64(new xdr.Uint64(BigInt(exitId)))],
        transfers: [],
        extend: claimRoom(this.#core),
      });
      if (returnValue?.switch().name !== "scvU64") {
        fail("rpc_error", "the claim returned no exit ID");
      }
      return { txHash: hash, requeuedAs: Number(scValToBigInt(returnValue)) };
    });
  }

  /**
   * Encodes the incoming or full viewing key, with a warning that it reveals the account's whole
   * history and future. disclosePayment proves a single payment instead.
   */
  exportViewingKey(kind: "incoming" | "full"): {
    readonly viewingKey: string;
    readonly warning: string;
  } {
    const { scan, keys } = this.#core;
    if (kind === "incoming") {
      return { viewingKey: encodeIncomingViewingKey(scan.incoming), warning: VIEWING_KEY_WARNING };
    }
    const full =
      keys ?? (scan.nkFold === undefined ? undefined : (scan.incoming as FullViewingKeys));
    if (full === undefined) fail("view_only", "an incoming viewing key cannot export a full one");
    return { viewingKey: encodeFullViewingKey(full), warning: VIEWING_KEY_WARNING };
  }

  /** Builds a payment disclosure for one note this wallet sent or received. */
  async disclosePayment(request: {
    readonly txHash: string;
    readonly leafIndex: number;
  }): Promise<PaymentDisclosure> {
    const { state, deployment, scan } = this.#core;
    return disclose(
      state,
      deployment.network,
      deployment.vault,
      request.txHash,
      request.leafIndex,
      (d) => {
        const key = addressKeyFor(scan.incoming, d);
        if (key === undefined) fail("invalid_argument", "a note has an invalid diversifier");
        return encodeAddress(scan.network, key.d, key.pkd);
      },
    );
  }
}
