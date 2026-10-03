import { expand, extract } from "@noble/hashes/hkdf";
import { sha512 } from "@noble/hashes/sha2";
import { xdr } from "@stellar/stellar-base";
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
import { type AccountLock, LeaseLock, lockName, webLock } from "../lock.ts";
import { type KeyValueStore, SealedStore } from "../storage.ts";
import { type TransactionSigner, invokeVault } from "../vault/invoke.ts";
import { type Core, newId } from "./core.ts";
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
import { type ExitPosition, applyExits, exitPosition } from "./exits.ts";
import { type Balance, type HistoryEntry, balanceOf, historyOf } from "./history.ts";
import { type Verification, createServices, verify } from "./services.ts";
import { type DepositEvent, type ExitEvent, IndexerSource, RpcEventSource } from "./sources.ts";
import { type ConfirmSpend, type Submission, spend, submissionOf } from "./spend.ts";
import { type Operation, type Plan, StateStore, type WalletState, emptyState } from "./state.ts";
import {
  type ScanKeys,
  advancePlans,
  applyDownload,
  checkRoot,
  crossCheck,
  downloadChain,
  isActive,
  resetUnlanded,
} from "./sync.ts";

/** Options shared by full and view-only wallets. */
export interface ConnectionOptions {
  readonly deployment: DeploymentName | Deployment;
  // Accepts a Deployment object that this release does not pin, for tests and local vaults.
  readonly allowUnpinnedDeployment?: boolean;
  readonly storage: KeyValueStore;
  readonly rpcUrl: string;
  // Every request goes through it, so the caller can route private-payment traffic via a proxy.
  readonly fetch?: FetchLike;
  // Service URLs other than the pinned ones; each must report the pinned vault and network.
  readonly indexers?: readonly string[];
  readonly relayers?: readonly string[];
  // Starts from a fresh state when the stored one cannot be read, instead of refusing to open. The
  // first sync then rebuilds notes and history from the chain; local records of submissions and
  // deposits that were only in the lost state are gone.
  readonly resetUnreadableState?: boolean;
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
  readonly newNotes: number;
  readonly source: "indexer" | "rpc";
  readonly rootVerified: boolean;
  // The indexer's new data matched the vault's RPC events for the same ledgers.
  readonly crossChecked: boolean;
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
  // The exit of an unshield that waits in the vault's exit queue, and what it still owes.
  readonly exitId: number | undefined;
  readonly payoutLeft: bigint | undefined;
  readonly operationId: string | undefined;
  readonly relayerStatus: string | undefined;
  // The payment may still land, or failed by the wallet's last reading of the chain only: paying
  // it again must go through retry, which spends the same notes, never through a new send.
  readonly mustRetry: boolean;
}

const VIEWING_KEY_WARNING =
  "A viewing key reveals the whole history and future of this private account to whoever holds " +
  "it, and cannot be revoked. To prove a single payment, use disclosePayment instead.";

// Parts of a split unshield follow the previous part's landing by one to six hours, at random.
const SPLIT_GAP_MS = { min: 3_600_000, max: 21_600_000 };

const LANDED: readonly Plan["state"][] = ["confirmed", "queued", "settled", "stranded", "claimed"];

function randomGap(): number {
  const r = new DataView(randomBytes(4).buffer).getUint32(0) / 2 ** 32;
  return SPLIT_GAP_MS.min + Math.floor(r * (SPLIT_GAP_MS.max - SPLIT_GAP_MS.min));
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
  #verification: Verification;
  #queue: Promise<unknown> = Promise.resolve();
  // The last sync found data that contradicts the chain; nothing of it was kept.
  #fault = false;

  private constructor(
    core: Core,
    fetchFn: FetchLike,
    states: StateStore,
    lock: AccountLock,
    verification: Verification,
  ) {
    this.#core = core;
    this.#fetch = fetchFn;
    this.#states = states;
    this.#lock = lock;
    this.#verification = verification;
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
    );
    const store = new SealedStore(options.storage, storeKey);
    const states = new StateStore(store);
    let state: WalletState;
    try {
      state = (await states.load()) ?? emptyState(deployment.deployLedger);
    } catch (err) {
      if (
        !(err instanceof CyphrasError) ||
        err.code !== "storage_unreadable" ||
        options.resetUnreadableState !== true
      ) {
        throw err;
      }
      await states.discard();
      state = emptyState(deployment.deployLedger);
    }
    const now = options.clock ?? (() => Date.now());
    const sleep =
      options.sleep ?? ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)));
    const lock = webLock(lockName(storeKey)) ?? new LeaseLock(store, now, sleep);
    const core: Core = {
      deployment,
      services,
      scan,
      keys,
      self: defaultAddressKey(scan.incoming),
      prover,
      artifacts,
      state,
      save: () => states.save(state),
      now,
      sleep,
    };
    const { verification } = await verify(services);
    return new PrivateWallet(core, fetchFn, states, lock, verification);
  }

  /**
   * Checks a payment disclosure against the chain without keys. The indexer serves the leaf and,
   * while RPC still holds the transaction, RPC confirms its events.
   */
  static async verifyDisclosure(
    doc: unknown,
    options: Pick<
      ConnectionOptions,
      "deployment" | "allowUnpinnedDeployment" | "rpcUrl" | "fetch" | "indexers"
    >,
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
    );
    const indexer = services.indexers[0];
    if (indexer === undefined) {
      fail("service_unavailable", "no indexer is configured", { service: "indexer" });
    }
    return verifyDisclosure(doc, deployment.network, deployment.vault, indexer, services.rpc);
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
    const from = Math.min(state.nullifierSince, state.lastLeafLedger || state.nullifierSince);
    return new RpcEventSource(
      services.rpc,
      deployment.vault,
      Math.max(deployment.deployLedger, from),
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
      resetUnlanded(plans);
      Object.assign(draft, emptyState(core.deployment.deployLedger), {
        revision,
        plans,
        deposits,
        operations,
      });
    }
    let summary: SyncSummary;
    try {
      summary = await this.#syncInto({ ...core, state: draft, save: async () => {} });
    } catch (err) {
      this.#fault =
        err instanceof CyphrasError &&
        (err.code === "indexer_fault" || err.code === "tree_unverified");
      throw err;
    }
    this.#fault = false;
    Object.assign(core.state, draft);
    await core.save();
    return summary;
  }

  async #syncInto(core: Core): Promise<SyncSummary> {
    const indexer = this.#indexer();
    let source: IndexerSource | RpcEventSource =
      indexer === undefined ? this.#rpcSource(core) : new IndexerSource(indexer);
    let download;
    try {
      download = await downloadChain(core.state, source, core.services.vault);
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
      download = await downloadChain(core.state, source, core.services.vault);
    }
    const { view, data } = download;
    let crossChecked = false;
    let events: {
      readonly exits: readonly ExitEvent[];
      readonly deposits: readonly DepositEvent[];
    };
    if (source.kind === "indexer") {
      const check = await crossCheck(core.services.rpc, core.deployment.vault, data);
      crossChecked = check.verified;
      events = check;
    } else {
      events = await source.events();
    }
    const check = checkRoot(data.tree, view.roots);
    if (check.state === "mismatch") {
      fail(
        "tree_unverified",
        "the synced tree contradicts the vault; nothing of this sync was kept",
      );
    }
    let newNotes = 0;
    // A plan or a deposit moves only on data the cross-check confirmed, or that RPC itself served.
    const checked = check.state === "verified" && (source.kind === "rpc" || crossChecked);
    if (check.state === "verified") {
      // Only leaves under a root the vault confirms count: notes at them, and spends of notes.
      newNotes = applyDownload(core.state, core.scan, data, checked);
      core.state.rootCheck = check;
      if (checked) advancePlans(core.state, data.horizon, view);
    } else {
      core.state.rootCheck = checkRoot(CommitmentTree.fromSnapshot(core.state.tree), view.roots);
    }
    const live = source.kind === "indexer" ? indexer : undefined;
    await trackDeposits(
      core,
      await live?.deposits().catch(() => undefined),
      events.deposits,
      checked ? data.horizon : undefined,
    );
    applyExits(core.state, events.exits, await live?.exits().catch(() => undefined));
    if (live !== undefined) await this.#pollRelayers(core);
    return {
      leafCount: core.state.tree.leafCount,
      newNotes,
      source: source.kind,
      rootVerified: core.state.rootCheck.state === "verified",
      crossChecked,
    };
  }

  // Asks only the relayer that submitted each pending plan about its own transaction.
  async #pollRelayers(core: Core): Promise<void> {
    for (const plan of core.state.plans) {
      const route = plan.route;
      if (plan.state !== "submitted" || route.kind !== "relayer" || plan.txHash === undefined) {
        continue;
      }
      const txHash = plan.txHash;
      const client = this.#relayerClients(route.url)[0] as RelayerClient;
      plan.relayerStatus = await client.status(txHash).catch(() => "unknown");
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
      payoutLeft: p.exit?.payoutLeft,
      operationId: p.operationId,
      relayerStatus: p.relayerStatus,
      mustRetry: isActive(p) || p.state === "dead",
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
      const { limits } = await this.#core.services.vault.instance();
      if (request.split === true && request.amount + maxFee > limits.maxDailyOutflow) {
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
    };
    this.#core.state.operations.push(op);
    await this.#core.save();
    await this.#nextPart(op, request.selfRelay, request.confirm);
    return this.#operationView(op);
  }

  #sent(op: Operation): bigint {
    return this.#core.state.plans
      .filter((p) => p.operationId === op.id && LANDED.includes(p.state))
      .reduce((s, p) => s + p.amount, 0n);
  }

  async #nextPart(
    op: Operation,
    signer: TransactionSigner | undefined,
    confirm: ConfirmSpend | undefined,
  ): Promise<void> {
    const remaining = op.total - this.#sent(op);
    const submission = await spend(this.#core, {
      kind: "unshield",
      to: op.to,
      amount: remaining < op.partSize ? remaining : op.partSize,
      maxFee: op.maxFee,
      relayers: op.route.kind === "relayers" ? this.#relayerClients(op.route.urls) : [],
      selfRelay: signer,
      // Later parts were confirmed with the whole operation; their warnings cannot stop them.
      confirm: confirm ?? (() => true),
      notBefore: undefined,
      inputs: undefined,
      retryOf: undefined,
      operationId: op.id,
      parts: Number((op.total + op.partSize - 1n) / op.partSize),
    });
    op.awaiting = submission.planId;
    await this.#core.save();
  }

  #operationView(op: Operation): OperationView {
    return {
      operationId: op.id,
      total: op.total,
      sent: this.#sent(op),
      parts: Number((op.total + op.partSize - 1n) / op.partSize),
      state: op.state,
      nextAt: op.nextAt,
      plans: this.#core.state.plans.filter((p) => p.operationId === op.id).map(submissionOf),
    };
  }

  /**
   * Sends the next part of each split unshield whose previous part has landed and whose random
   * gap has passed. A self-relayed operation needs its signer again.
   */
  continueOperations(signer?: TransactionSigner): Promise<OperationView[]> {
    return this.#run(async () => {
      await this.#sync(false);
      const { state } = this.#core;
      for (const op of state.operations) {
        if (op.state !== "active") continue;
        const awaiting = state.plans.find((p) => p.id === op.awaiting);
        if (awaiting !== undefined && isActive(awaiting)) continue;
        if (awaiting !== undefined) {
          op.awaiting = undefined;
          // A part that never landed goes again at once; one that landed starts the gap.
          op.nextAt = LANDED.includes(awaiting.state)
            ? this.#core.now() + randomGap()
            : this.#core.now();
        }
        if (this.#sent(op) >= op.total) {
          op.state = "done";
          continue;
        }
        if (this.#core.now() < op.nextAt) continue;
        if (op.route.kind === "self" && signer?.publicKey !== op.route.account) continue;
        await this.#nextPart(op, op.route.kind === "self" ? signer : undefined, undefined);
      }
      await this.#core.save();
      return state.operations.map((op) => this.#operationView(op));
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
      });
    });
  }

  /** Where a queued payout of this wallet stands in the vault's exit queue, and when it is due. */
  async exitPosition(planId: string): Promise<ExitPosition | undefined> {
    const plan = this.#core.state.plans.find((p) => p.id === planId);
    if (plan?.exit === undefined || plan.state !== "queued") return undefined;
    const queue = await this.#indexer()?.exits();
    if (queue === undefined) return undefined;
    return exitPosition(queue, plan.exit.id);
  }

  /**
   * Pays queued exits in FIFO order, up to `max`, as far as today's outflow window reaches; anyone
   * may call it.
   */
  releaseExits(signer: TransactionSigner, max = 10): Promise<{ readonly txHash: string }> {
    return this.#run(async () => {
      await this.#ensureVerified();
      const { hash } = await invokeVault(this.#invokeContext(), signer, {
        fn: "release",
        args: [xdr.ScVal.scvU32(max)],
        transfers: [],
      });
      return { txHash: hash };
    });
  }

  /**
   * Pays the parts of a stranded exit that its recipient and relayer can now receive, each part
   * whole within today's outflow window; anyone may submit it.
   */
  claimExit(exitId: number, signer: TransactionSigner): Promise<{ readonly txHash: string }> {
    return this.#run(async () => {
      await this.#ensureVerified();
      const { hash } = await invokeVault(this.#invokeContext(), signer, {
        fn: "claim",
        args: [xdr.ScVal.scvU64(new xdr.Uint64(BigInt(exitId)))],
        transfers: [],
      });
      return { txHash: hash };
    });
  }

  #invokeContext() {
    const { services, deployment } = this.#core;
    return {
      rpc: services.rpc,
      networkPassphrase: deployment.networkPassphrase,
      vault: deployment.vault,
      sleep: (ms: number) => this.#core.sleep(ms),
    };
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
