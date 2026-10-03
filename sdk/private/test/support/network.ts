// An indexer and a relayer that answer as the services do, over the vault model, and a fetch that
// routes the SDK's requests to them and to the mock RPC.
import { createHash } from "node:crypto";
import {
  Asset,
  Keypair,
  StrKey,
  type Transaction,
  TransactionBuilder,
} from "@stellar/stellar-base";
import { bigIntToBytesBE, bytesToHex } from "../../src/bytes.ts";
import type { Deployment } from "../../src/deployments.ts";
import { computeDomain } from "../../src/domain.ts";
import {
  extDataFromJson,
  txProofFromJson,
  type ExtDataJson,
  type TxProofJson,
} from "../../src/extdata.ts";
import { NETWORK_PASSPHRASES } from "../../src/keys.ts";
import type { FetchLike } from "../../src/net/http.ts";
import type { TransactionSigner } from "../../src/vault/invoke.ts";
import { MockRpc, RpcFailure, keypairFor } from "./rpc.ts";
import { trapdoorPins } from "./trapdoor.ts";
import { type Exit, type Limits, MockVault, type Moment } from "./vault.ts";

export const RPC = "http://rpc.test";
export const INDEXER = "http://indexer.test";
export const RELAYER = "http://relayer.test";
const PASSPHRASE = NETWORK_PASSPHRASES.testnet;
export const XLM = 10_000_000n;

export const DEFAULT_LIMITS: Limits = {
  minDeposit: 1n * XLM,
  maxDeposit: 2_500n * XLM,
  maxDailyPerDepositor: 5_000n * XLM,
  tvlCap: 25_000n * XLM,
  maxDailyOutflow: 5_000n * XLM,
  maxFee: 5n * XLM,
  largeDepositThreshold: 500n * XLM,
};

// The end of the UTC day by which releases have paid each queued exit at the latest, as the
// indexer computes it: from the day of max(now, haltedUntil), as many more days as the exits up to
// and including it owe, in whole windows.
// What a queued exit can take from the windows, as the services count it: what it owes and, in a
// native vault, up to 1 XLM of a window that release leaves unused rather than pay a first part
// below 1 XLM to an account that may not exist yet.
function takes(e: Exit): bigint {
  const first = e.payout > 0n && e.payout === e.queuedPayout;
  const account = e.recipient.startsWith("G") || e.recipient.startsWith("M");
  return e.payout + e.fee + (first && account ? XLM - 1n : 0n);
}

function paidBy(
  owed: readonly bigint[],
  now: number,
  haltedUntil: number,
  maxDaily: bigint,
): number[] {
  const day = Math.floor(Math.max(now, haltedUntil) / 86_400);
  let total = 0n;
  return owed.map((o) => {
    total += o;
    const days = Number((total + maxDaily - 1n) / maxDaily);
    return (day + days + 1) * 86_400 - 1;
  });
}

// The ledger, time and transaction of a step in an exit's life, as the indexer names them.
const moment = (step: string, m: Moment | undefined): Record<string, unknown> =>
  m === undefined
    ? {}
    : { [`${step}_ledger`]: m.ledger, [`${step}_at`]: Number(m.at), [`${step}_tx`]: m.tx };

// Field elements as the indexer serves them: 32 bytes of hex with no prefix.
const fieldHex = (x: bigint): string => bytesToHex(bigIntToBytesBE(x, 32));

const json = (status: number, body: unknown): Response =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

const PROOF_KEYS = [
  "a",
  "b",
  "c",
  "root",
  "public_amount",
  "ext_data_hash",
  "input_nullifiers",
  "output_commitments",
];
const EXT_KEYS = [
  "vault",
  "network_id",
  "deadline",
  "ext_amount",
  "fee",
  "recipient",
  "relayer",
  "encrypted_output0",
  "encrypted_output1",
];

function exactKeys(
  value: unknown,
  required: readonly string[],
  optional: readonly string[] = [],
): value is Record<string, unknown> {
  return (
    typeof value === "object" &&
    value !== null &&
    required.every((k) => k in value) &&
    Object.keys(value).every((k) => required.includes(k) || optional.includes(k))
  );
}

const isHex = (value: unknown, bytes: number): boolean =>
  typeof value === "string" && value.length === 2 * bytes && /^[0-9a-f]*$/.test(value);

// The relayer's strict parsing: exactly the known members, and binary values as lowercase hex of
// exact length with no prefix.
function wellFormed(body: unknown): boolean {
  if (!exactKeys(body, ["proof", "ext"], ["not_before"])) return false;
  const { proof, ext } = body;
  if (!exactKeys(proof, PROOF_KEYS) || !exactKeys(ext, EXT_KEYS)) return false;
  const pairs = [proof["input_nullifiers"], proof["output_commitments"]];
  if (!pairs.every((p) => Array.isArray(p) && p.length === 2)) return false;
  const fields = [
    proof["root"],
    proof["public_amount"],
    proof["ext_data_hash"],
    ...(pairs.flat() as unknown[]),
  ];
  return (
    isHex(proof["a"], 64) &&
    isHex(proof["b"], 128) &&
    isHex(proof["c"], 64) &&
    fields.every((f) => isHex(f, 32)) &&
    isHex(ext["network_id"], 32) &&
    isHex(ext["encrypted_output0"], 181) &&
    isHex(ext["encrypted_output1"], 181)
  );
}

export class MockIndexer {
  readonly vault: MockVault;
  readonly networkId: string;
  ready = true;
  nullifierPage = 4096;
  identity: { vault: string; networkId: string } | undefined;
  // Test hooks: change what the indexer serves.
  tamperLeaf: ((index: number, cm: string) => string) | undefined;
  hideNullifiers = false;
  // Serves only the leaves below this index, as an indexer that lags the vault.
  leafLimit: number | undefined;
  // The ledger the nullifiers reply claims to be complete to, when it lags the listed ones.
  completeTo: number | undefined;
  down = false;
  requests: string[] = [];

  constructor(vault: MockVault, networkId: string) {
    this.vault = vault;
    this.networkId = networkId;
  }

  handle(url: URL): Response {
    if (this.down) throw new TypeError("connection refused");
    this.requests.push(url.pathname + url.search);
    const v = this.vault;
    const identity = {
      vault: this.identity?.vault ?? v.address,
      network_id: this.identity?.networkId ?? this.networkId,
    };
    switch (url.pathname) {
      case "/v1/health":
        return json(this.ready ? 200 : 503, {
          ready: this.ready,
          ...(this.ready ? {} : { code: "lagging" }),
          ...identity,
          deploy_ledger: 10,
          latest_ledger: v.ledger,
          ingested_ledger: v.ledger,
          reconciled_ledger: v.ledger,
          leaf_count: v.tree.leafCount,
          root: fieldHex(v.tree.root()),
          nullifier_count: v.nullifiers.size,
          pending_count: v.pending.size,
        });
      case "/v1/leaves": {
        const page = Number(url.searchParams.get("page"));
        const end = Math.min(page * 1024 + 1024, this.leafLimit ?? Number.POSITIVE_INFINITY);
        const leaves = v.leaves.slice(page * 1024, end).map((l) => {
          const cm = fieldHex(l.cm);
          return {
            index: l.index,
            commitment: this.tamperLeaf?.(l.index, cm) ?? cm,
            ciphertext: bytesToHex(l.ciphertext),
            ledger: l.ledger,
            tx_hash: l.txHash,
          };
        });
        return json(200, {
          page,
          leaves,
          complete: leaves.length === 1024,
          ingested_ledger: v.ledger,
        });
      }
      case "/v1/nullifiers": {
        const since = Number(url.searchParams.get("since_ledger"));
        const offset = Number(url.searchParams.get("cursor") ?? "0");
        const all = [...v.nullifiers.entries()]
          .filter(([, n]) => n.ledger >= since && !this.hideNullifiers)
          .sort(([, a], [, b]) => a.ledger - b.ledger);
        const slice = all.slice(offset, offset + this.nullifierPage);
        const more = offset + slice.length < all.length;
        return json(200, {
          nullifiers: slice.map(([nf, n]) => ({
            nullifier: fieldHex(nf),
            ledger: n.ledger,
            tx_hash: n.txHash,
          })),
          next_cursor: more ? String(offset + slice.length) : null,
          complete_to: this.completeTo ?? v.ledger,
        });
      }
      case "/v1/deposits":
        return json(200, {
          pending: [...v.pending.entries()].map(([id, d]) => ({
            id,
            depositor: d.depositor,
            amount: d.amount.toString(),
            created_at: Number(d.createdAt),
            earliest_admission: Number(d.createdAt + d.delay),
            attested: id <= v.attestedUpTo,
            flag_reason: d.flag ?? null,
            flagged_at: d.flag === undefined ? null : Number(d.flaggedAt),
          })),
          resolved: v.resolved.map((r) => ({
            id: r.id,
            depositor: r.depositor,
            amount: r.amount.toString(),
            created_at: Number(r.createdAt),
            outcome: r.outcome,
            reason: r.reason ?? 0,
            resolved_at: Number(r.resolvedAt),
            leaf_index0: r.leafIndices?.[0] ?? null,
            leaf_index1: r.leafIndices?.[1] ?? null,
          })),
          attested_up_to: v.attestedUpTo,
          complete_to: v.ledger,
        });
      case "/v1/stats":
        return json(200, {
          leaf_count: v.tree.leafCount,
          admitted_deposits: v.resolved.filter((r) => r.outcome === "admitted").length,
          distinct_depositors: new Set(v.resolved.map((r) => r.depositor)).size,
          pending_deposits: v.pending.size,
        });
      case "/v1/exits": {
        const now = Number(v.timestamp);
        const today = Math.floor(now / 86_400);
        const used = v.outflowDay === BigInt(today) ? v.outflow : 0n;
        const queued = [...v.exits.values()].sort((a, b) => a.id - b.id);
        const paid = paidBy(
          queued.map(takes),
          now,
          Number(v.haltedUntil),
          v.limits.maxDailyOutflow,
        );
        const entry = (e: Exit, state: string) => ({
          id: e.id,
          state,
          payout: e.queuedPayout.toString(),
          fee: e.queuedFee.toString(),
          payout_paid: (e.queuedPayout - e.movedPayout - e.payout).toString(),
          fee_paid: (e.queuedFee - e.movedFee - e.fee).toString(),
          payout_requeued: e.movedPayout.toString(),
          fee_requeued: e.movedFee.toString(),
          payout_left: e.payout.toString(),
          fee_left: e.fee.toString(),
          recipient: e.recipient,
          relayer: e.relayer,
          queued_at: Number(e.queuedAt),
          queued_ledger: e.ledger,
          tx_hash: e.txHash,
          ...(e.requeuedFrom === undefined ? {} : { requeued_from: e.requeuedFrom }),
          ...moment("stranded", e.stranded),
          ...(e.requeuedTo.length === 0 ? {} : { requeued_to: e.requeuedTo }),
          ...moment("requeued", e.requeued),
          ...moment("settled", e.settled),
        });
        return json(200, {
          head: v.exitHead,
          tail: v.exitTail,
          queued_total: v.queuedTotal.toString(),
          max_daily_outflow: v.limits.maxDailyOutflow.toString(),
          window: { day: today, used: used.toString(), resets_at: (today + 1) * 86_400 },
          halted_until: Number(v.haltedUntil),
          exits: [
            ...queued.map((e, i) => ({
              ...entry(
                e,
                e.payout === e.queuedPayout && e.fee === e.queuedFee ? "queued" : "paid_in_part",
              ),
              position: e.id - v.exitHead,
              paid_by: paid[i],
            })),
            ...[
              ...[...v.stranded.values()].map((e) => entry(e, "stranded")),
              ...v.requeuedExits.map((e) => entry(e, "requeued")),
              ...v.settledExits.map((e) => entry(e, "settled")),
            ].sort((a, b) => a.id - b.id),
          ],
          complete_to: v.ledger,
        });
      }
      default:
        return json(404, { error: "not_found" });
    }
  }
}

export class MockRelayer {
  readonly rpc: MockRpc;
  readonly vault: MockVault;
  readonly networkId: string;
  readonly feeAddress: string;
  readonly channel: Keypair;
  fee = 1n * XLM;
  tier = 100_000n;
  asset = "native";
  ready = true;
  // Test hook: a fee address the quote names instead of the one the health reports.
  quoteFeeAddress: string | undefined;
  // Test hooks: errors to answer submissions with, in order.
  failures: { error: string; reason?: number }[] = [];
  // The nullifiers of requests held in memory, which a second submission may not claim.
  inFlight = new Set<string>();
  submissions: { proof: TxProofJson; ext: ExtDataJson; notBefore: number | undefined }[] = [];
  status = new Map<string, string>();
  // Requests held until their not_before, by the ID the reply gave, with the hash once sent;
  // releaseHeld sends them.
  readonly heldRequests = new Map<
    string,
    { hash: string | undefined; failure?: { code: string; reason: number } }
  >();
  held: (() => void)[] = [];
  // Test hook: the screening refuses held requests when they are due, with this reason.
  refuseHeld: number | undefined;

  constructor(rpc: MockRpc, networkId: string, feeAddress: string) {
    this.rpc = rpc;
    this.vault = rpc.vault;
    this.networkId = networkId;
    this.feeAddress = feeAddress;
    this.channel = keypairFor("relayer channel");
  }

  handle(url: URL, body: unknown): Response {
    const v = this.vault;
    if (url.pathname === "/v1/health") {
      return json(this.ready ? 200 : 503, {
        ready: this.ready,
        vault: v.address,
        network_id: this.networkId,
        fee_address: this.feeAddress,
        max_fee: v.limits.maxFee.toString(),
        channels: 4,
      });
    }
    if (url.pathname === "/v1/quote") {
      if (this.fee > v.limits.maxFee) return json(503, { error: "unavailable" });
      return json(200, {
        fee: this.fee.toString(),
        asset: this.asset,
        tier: this.tier.toString(),
        margin_bps: 500,
        valid_until: Number(v.timestamp) + 300,
        fee_address: this.quoteFeeAddress ?? this.feeAddress,
        vault: v.address,
        network_id: this.networkId,
      });
    }
    if (url.pathname === "/v1/submit") return this.#submit(body as Record<string, unknown>);
    if (url.pathname.startsWith("/v1/tx/")) {
      const hash = url.pathname.slice("/v1/tx/".length);
      return this.status.has(hash)
        ? json(200, this.#txStatus(hash))
        : json(404, { error: "not_found" });
    }
    if (url.pathname.startsWith("/v1/held/")) {
      const request = this.heldRequests.get(url.pathname.slice("/v1/held/".length));
      if (request === undefined) return json(404, { error: "not_found" });
      if (request.failure !== undefined) return json(200, { status: "failed", ...request.failure });
      if (request.hash === undefined) return json(200, { status: "held" });
      return json(200, { ...this.#txStatus(request.hash), hash: request.hash });
    }
    return json(404, { error: "not_found" });
  }

  // A transaction's status as the relayer serves it, with the exit it queued.
  #txStatus(hash: string): Record<string, unknown> {
    const status = this.status.get(hash);
    if (status === "failed") return { status, code: "rejected" };
    const exit = [...this.vault.exits.values(), ...this.vault.settledExits].find(
      (e) => e.txHash === hash,
    );
    return exit === undefined ? { status } : { status, exit_id: exit.id };
  }

  releaseHeld(): void {
    for (const send of this.held.splice(0)) send();
  }

  // Held requests live in memory only, so a restart forgets them and their claims.
  restart(): void {
    this.held = [];
    this.heldRequests.clear();
    this.inFlight.clear();
  }

  // Strict parsing, then the vault call with a channel account as the submitter.
  #submit(body: Record<string, unknown>): Response {
    const failure = this.failures.shift();
    if (failure !== undefined) return json(400, failure);
    if (!wellFormed(body)) return json(400, { error: "bad_request" });
    let proof;
    let ext;
    try {
      proof = txProofFromJson(body["proof"] as TxProofJson);
      ext = extDataFromJson(body["ext"] as ExtDataJson);
    } catch {
      return json(400, { error: "bad_request" });
    }
    if (ext.vault !== this.vault.address || bytesToHex(ext.networkId) !== this.networkId) {
      return json(400, { error: "wrong_vault" });
    }
    if (ext.extAmount > 0n || ext.relayer !== this.feeAddress)
      return json(400, { error: "bad_request" });
    if (ext.fee < this.fee) return json(400, { error: "fee_too_low" });
    if (ext.fee > this.vault.limits.maxFee) return json(400, { error: "fee_above_cap" });
    const key = proof.inputNullifiers.map(String).join(":");
    if (proof.inputNullifiers.some((nf) => this.inFlight.has(nf.toString()))) {
      return json(409, { error: "duplicate" });
    }
    const notBefore = body["not_before"] as number | undefined;
    this.submissions.push({
      proof: body["proof"] as TxProofJson,
      ext: body["ext"] as ExtDataJson,
      notBefore,
    });
    const hash = createHash("sha256")
      .update(`relayed/${key}/${this.submissions.length}`)
      .digest("hex");
    const send = (): boolean => {
      try {
        this.rpc.run(hash, () => this.vault.transact(proof, ext, this.channel.publicKey()));
        this.status.set(hash, "success");
        return true;
      } catch {
        this.status.set(hash, "failed");
        return false;
      }
    };
    if (notBefore !== undefined && notBefore > Number(this.vault.timestamp)) {
      const id = createHash("sha256")
        .update(`held/${key}/${this.submissions.length}`)
        .digest("hex")
        .slice(0, 32);
      const claimed = proof.inputNullifiers.map(String);
      for (const nf of claimed) this.inFlight.add(nf);
      this.heldRequests.set(id, { hash: undefined });
      this.held.push(() => {
        for (const nf of claimed) this.inFlight.delete(nf);
        if (this.refuseHeld !== undefined) {
          const failure = { code: "refused", reason: this.refuseHeld };
          this.heldRequests.set(id, { hash: undefined, failure });
          return;
        }
        send();
        this.heldRequests.set(id, { hash });
      });
      return json(202, { held: true, id });
    }
    return send() ? json(202, { hash }) : json(422, { error: "rejected" });
  }
}

export interface World {
  readonly vault: MockVault;
  readonly rpc: MockRpc;
  readonly indexer: MockIndexer;
  readonly relayer: MockRelayer;
  readonly deployment: Deployment;
  readonly fetch: FetchLike;
  readonly requests: string[];
  readonly clock: () => number;
  signer(label: string): TransactionSigner & { readonly keypair: Keypair };
  advance(seconds: number): void;
  // The keeper and the screening service: attest and admit every eligible deposit.
  admitAll(): void;
  // Other users' transactions adding `pairs` pairs of leaves, in one ledger.
  fill(pairs: number): void;
}

// The pool asset is native unless `asset` names an issued one as CODE:ISSUER.
export async function createWorld(
  options: { limits?: Partial<Limits>; asset?: string } = {},
): Promise<World> {
  const networkId = createHash("sha256").update(PASSPHRASE).digest();
  const vaultAddress = StrKey.encodeContract(createHash("sha256").update("test vault").digest());
  const assetName = options.asset ?? "native";
  const [code, issuer] = assetName.split(":") as [string, string | undefined];
  const token = (issuer === undefined ? Asset.native() : new Asset(code, issuer)).contractId(
    PASSPHRASE,
  );
  const vault = new MockVault({
    address: vaultAddress,
    token,
    networkId: new Uint8Array(networkId),
    domain: computeDomain("testnet", assetName),
    wasmHash: createHash("sha256").update("test vault wasm").digest("hex"),
    limits: { ...DEFAULT_LIMITS, ...options.limits },
  });
  const rpc = new MockRpc(vault, PASSPHRASE);
  const feeAddress = keypairFor("relayer fee").publicKey();
  const indexer = new MockIndexer(vault, networkId.toString("hex"));
  const relayer = new MockRelayer(rpc, networkId.toString("hex"), feeAddress);
  relayer.asset = assetName;
  vault.native = issuer === undefined;
  const requests: string[] = [];
  const deployment: Deployment = {
    id: "testnet/test",
    network: "testnet",
    networkPassphrase: PASSPHRASE,
    vault: vaultAddress,
    asset: { contract: token, name: assetName },
    domain: vault.domain,
    deployLedger: 10,
    vaultWasmHash: vault.wasmHash,
    artifacts: await trapdoorPins(),
    indexers: [INDEXER],
    relayers: [{ url: RELAYER, feeAddress }],
    feeTier: relayer.tier,
  };
  const fetchFn: FetchLike = async (input, init) => {
    const url = new URL(input);
    requests.push(`${url.origin}${url.pathname}`);
    const body =
      init?.body === undefined || init.body === null ? undefined : JSON.parse(String(init.body));
    if (url.origin === RPC) {
      const request = body as { id: number; method: string; params: Record<string, unknown> };
      try {
        return json(200, {
          jsonrpc: "2.0",
          id: request.id,
          result: rpc.handle(request.method, request.params ?? {}),
        });
      } catch (err) {
        if (err instanceof RpcFailure) {
          return json(200, {
            jsonrpc: "2.0",
            id: request.id,
            error: { code: err.code, message: err.message },
          });
        }
        throw err;
      }
    }
    if (url.origin === INDEXER) return indexer.handle(url);
    if (url.origin === RELAYER) return relayer.handle(url, body);
    throw new TypeError(`no route to ${url.origin}`);
  };
  rpc.account(relayer.channel);
  rpc.account(keypairFor("relayer fee"));
  vault.accountExists = (account) =>
    !StrKey.isValidEd25519PublicKey(account) || rpc.accounts.has(account);
  vault.createAccount = (account) => rpc.createAccount(account);
  const world: World = {
    vault,
    rpc,
    indexer,
    relayer,
    deployment,
    fetch: fetchFn,
    requests,
    clock: () => Number(vault.timestamp) * 1000,
    signer(label: string) {
      const keypair = keypairFor(label);
      if (!rpc.accounts.has(keypair.publicKey())) rpc.account(keypair);
      return {
        keypair,
        publicKey: keypair.publicKey(),
        async signTransaction(envelope: string, passphrase: string): Promise<string> {
          const tx = TransactionBuilder.fromXDR(envelope, passphrase) as Transaction;
          tx.sign(keypair);
          return tx.toXDR();
        },
      };
    },
    advance(seconds: number) {
      vault.timestamp += BigInt(seconds);
      vault.ledger += Math.ceil(seconds / 5);
    },
    fill(pairs: number) {
      rpc.run(createHash("sha256").update(`fill ${vault.ledger}`).digest("hex"), () =>
        vault.insertFiller(pairs),
      );
    },
    admitAll() {
      const ids = [...vault.pending.keys()].sort((a, b) => a - b);
      const last = ids[ids.length - 1];
      if (last === undefined) return;
      rpc.run(createHash("sha256").update(`attest ${last} ${vault.ledger}`).digest("hex"), () =>
        vault.attest(last),
      );
      rpc.run(createHash("sha256").update(`admit ${vault.ledger}`).digest("hex"), () =>
        vault.admit(ids),
      );
    },
  };
  return world;
}

/** Rewrites the JSON replies of indexer endpoints, to play an indexer that lies. */
export function rewritingFetch(
  world: World,
  rewrite: Readonly<Record<string, (body: Record<string, unknown>) => unknown>>,
): FetchLike {
  return async (input, init) => {
    const res = await world.fetch(input, init);
    const url = new URL(input);
    const fn = url.origin === INDEXER ? rewrite[url.pathname] : undefined;
    if (fn === undefined || res.status !== 200) return res;
    const body = fn((await res.json()) as Record<string, unknown>);
    return new Response(JSON.stringify(body), { status: 200 });
  };
}
