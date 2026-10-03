import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, it } from "node:test";
import { CyphrasError } from "../../src/errors.ts";
import { P } from "../../src/field.ts";
import { Fields, type FetchLike, MAX_REPLY_BYTES } from "../../src/net/http.ts";
import { IndexerClient } from "../../src/net/indexer.ts";
import { RelayerClient } from "../../src/net/relayer.ts";
import { SorobanRpc } from "../../src/net/rpc.ts";
import { IndexerSource } from "../../src/wallet/sources.ts";
import { vaultErrorName } from "../../src/vault/errors.ts";
import { parseVaultErrors } from "../../scripts/vault-errors.ts";
import { SDK_ROOT } from "../helpers.ts";
import { ERROR } from "../support/vault.ts";

const reply =
  (status: number, body: unknown): FetchLike =>
  async () =>
    new Response(JSON.stringify(body), { status });

const isCode = (code: string) => (err: unknown) => err instanceof CyphrasError && err.code === code;

describe("vault errors", () => {
  it("map every code of the contract source copied from the contracts branch", () => {
    const source = readFileSync(join(SDK_ROOT, "test", "fixtures", "vault-error.rs"), "utf8");
    const errors = parseVaultErrors(source);
    assert.ok(errors.size >= 40);
    for (const [code, name] of errors) assert.equal(vaultErrorName(code), name);
    // Codes start at 100, clear of the Stellar Asset Contract's own small codes.
    assert.equal(vaultErrorName(103), "Halted");
    assert.equal(vaultErrorName(143), "NothingClaimable");
    assert.equal(vaultErrorName(4), undefined);
  });

  it("agree with the codes the vault model refuses with", () => {
    for (const [name, code] of Object.entries(ERROR)) assert.equal(vaultErrorName(code), name);
  });
});

describe("strict reply fields", () => {
  const f = Fields.of(
    {
      a: "0x" + "00".repeat(31) + "05",
      b: "ff".repeat(32),
      c: (P + 1n).toString(16).padStart(64, "0"),
      d: "-12",
      e: "012",
      bytes: "abcd",
      upper: "ABCD",
    },
    "indexer_fault",
    "reply",
  );

  it("reads field elements with or without 0x and only below p", () => {
    assert.equal(f.field("a"), 5n);
    assert.throws(() => f.field("b"), isCode("indexer_fault"));
    assert.throws(() => f.field("c"), isCode("indexer_fault"));
  });

  it("reads decimal amounts and exact-length lowercase hex", () => {
    assert.equal(f.amount("d"), -12n);
    assert.throws(() => f.amount("e"), isCode("indexer_fault"));
    assert.deepEqual(f.bytes("bytes", 2), Uint8Array.of(0xab, 0xcd));
    assert.throws(() => f.bytes("bytes", 3), isCode("indexer_fault"));
    assert.throws(() => f.bytes("upper", 2), isCode("indexer_fault"));
    assert.throws(() => f.string("missing"), isCode("indexer_fault"));
  });
});

describe("indexer client", () => {
  const leaf = (index: number) => ({
    index,
    commitment: "0x" + index.toString(16).padStart(64, "0"),
    ciphertext: "00".repeat(181),
    ledger: 7,
    tx_hash: "aa".repeat(32),
  });

  it("accepts a page of contiguous leaves", async () => {
    const indexer = new IndexerClient(
      "http://i",
      reply(200, { page: 1, leaves: [leaf(1024), leaf(1025)] }),
    );
    const leaves = await indexer.leaves(1);
    assert.deepEqual(
      leaves.map((l) => l.index),
      [1024, 1025],
    );
  });

  it("refuses another page, a gap or a short ciphertext", async () => {
    for (const body of [
      { page: 0, leaves: [leaf(1024)] },
      { page: 1, leaves: [leaf(1024), leaf(1026)] },
      { page: 1, leaves: [{ ...leaf(1024), ciphertext: "00".repeat(180) }] },
    ]) {
      await assert.rejects(
        new IndexerClient("http://i", reply(200, body)).leaves(1),
        isCode("indexer_fault"),
      );
    }
  });

  it("refuses nullifiers out of chain order and reports a busy indexer as unavailable", async () => {
    const n = (ledger: number) => ({
      nullifier: "0x" + "01".repeat(32),
      ledger,
      tx_hash: "bb".repeat(32),
    });
    const unordered = reply(200, {
      nullifiers: [n(9), n(8)],
      next_cursor: null,
      complete_to: 10,
    });
    await assert.rejects(
      new IndexerClient("http://i", unordered).nullifiers(5),
      isCode("indexer_fault"),
    );
    await assert.rejects(
      new IndexerClient("http://i", reply(503, { ready: false, code: "lagging" })).leaves(0),
      isCode("service_unavailable"),
    );
    await assert.rejects(
      new IndexerClient("http://i", async () => {
        throw new TypeError("offline");
      }).leaves(0),
      (err: unknown) =>
        isCode("service_unavailable")(err) && !(err as Error).message.includes("http://i"),
    );
  });

  it("leaves nullifiers past the complete-to ledger for the next sync", async () => {
    const n = (ledger: number, byte: string) => ({
      nullifier: byte.repeat(32),
      ledger,
      tx_hash: "bb".repeat(32),
    });
    const indexer = new IndexerClient(
      "http://i",
      reply(200, { nullifiers: [n(9, "01"), n(12, "02")], next_cursor: null, complete_to: 10 }),
    );
    const set = await new IndexerSource(indexer, 64).nullifiers(5);
    assert.deepEqual(
      set.nullifiers.map((x) => x.ledger),
      [9],
    );
    assert.equal(set.completeToLedger, 10);
  });

  it("stops at its page cap with the nullifiers complete up to the last ledger before it", async () => {
    const n = (ledger: number, byte: string) => ({
      nullifier: byte.repeat(32),
      ledger,
      tx_hash: "bb".repeat(32),
    });
    const pages: Record<string, unknown>[] = [
      { nullifiers: [n(9, "01"), n(10, "02")], next_cursor: "2", complete_to: 20 },
      { nullifiers: [n(10, "03"), n(12, "04")], next_cursor: "4", complete_to: 20 },
      { nullifiers: [n(15, "05")], next_cursor: null, complete_to: 20 },
    ];
    let served = 0;
    const indexer = new IndexerClient("http://i", async () => {
      return new Response(JSON.stringify(pages[served++]), { status: 200 });
    });
    const set = await new IndexerSource(indexer, 2).nullifiers(5);
    assert.equal(served, 2);
    assert.equal(set.completeToLedger, 11);
    assert.deepEqual(
      set.nullifiers.map((x) => x.ledger),
      [9, 10, 10],
    );
  });

  it("refuses a reply larger than any a service sends", async () => {
    const huge = new IndexerClient(
      "http://i",
      reply(200, { page: 0, leaves: [], padding: "x".repeat(MAX_REPLY_BYTES) }),
    );
    await assert.rejects(huge.leaves(0), isCode("service_unavailable"));
  });

  it("reads the entry queue with null for absent values", async () => {
    const depositor = "GA53HZCSOZI5ZUDYCMYXXUGHO7XEZSM3BYW4M5FGSTYGKWMGVL7QLFB3";
    const pending = {
      id: 3,
      depositor,
      amount: "50000000",
      created_at: 1_759_000_000,
      earliest_admission: null,
      attested: false,
      flag_reason: 2,
      flagged_at: 1_759_000_100,
    };
    const resolved = {
      id: 2,
      depositor,
      amount: "10000000",
      created_at: 1_758_990_000,
      outcome: "admitted",
      reason: 0,
      resolved_at: 1_758_999_000,
      leaf_index0: 6,
      leaf_index1: 7,
    };
    const body = { pending: [pending], resolved: [resolved], attested_up_to: 2, complete_to: 90 };
    const queue = await new IndexerClient("http://i", reply(200, body)).deposits();
    assert.equal(queue.pending[0]?.earliestAdmission, undefined);
    assert.deepEqual(queue.pending[0]?.flag, { reason: 2, flaggedAt: 1_759_000_100 });
    assert.deepEqual(queue.resolved[0]?.leafIndices, [6, 7]);
    const unflagged = { ...pending, flag_reason: null, flagged_at: null };
    const plain = await new IndexerClient(
      "http://i",
      reply(200, { ...body, pending: [unflagged] }),
    ).deposits();
    assert.equal(plain.pending[0]?.flag, undefined);
    await assert.rejects(
      new IndexerClient(
        "http://i",
        reply(200, { ...body, resolved: [{ ...resolved, leaf_index1: null }] }),
      ).deposits(),
      isCode("indexer_fault"),
    );
  });
});

describe("indexer exit queue", () => {
  const exit = (id: number, state: string, position?: number) => ({
    id,
    state,
    ...(position === undefined ? {} : { position, paid_by: 1_759_100_000 }),
    payout: "100",
    fee: "1",
    payout_paid: "0",
    fee_paid: "0",
    payout_left: "100",
    fee_left: "1",
    tx_hash: "cc".repeat(32),
  });
  const queue = (exits: unknown[], head = 3, tail = 5) =>
    new IndexerClient("http://i", reply(200, { head, tail, exits, complete_to: 50 })).exits();

  it("reads queued, stranded and settled exits around the head", async () => {
    const q = await queue([
      exit(3, "paid_in_part", 0),
      exit(4, "queued", 1),
      exit(1, "stranded"),
      exit(2, "settled"),
    ]);
    assert.deepEqual(
      q.exits.map((e) => [e.id, e.state, e.position]),
      [
        [3, "paid_in_part", 0],
        [4, "queued", 1],
        [1, "stranded", undefined],
        [2, "settled", undefined],
      ],
    );
  });

  it("refuses a queue with a gap, a misplaced exit or an unknown state", async () => {
    for (const exits of [
      [exit(3, "queued", 0)],
      [exit(3, "queued", 0), exit(5, "queued", 2)],
      [exit(3, "queued", 0), exit(4, "queued", 1), exit(4, "stranded")],
      [exit(3, "queued", 0), exit(4, "lost", 1)],
    ]) {
      await assert.rejects(queue(exits), isCode("indexer_fault"));
    }
  });

  it("reads a requeued exit and the links between it and the exits claims queued from it", async () => {
    const q = await queue([
      exit(3, "queued", 0),
      { ...exit(4, "queued", 1), requeued_from: 1 },
      { ...exit(1, "requeued"), requeued_to: [4] },
    ]);
    assert.deepEqual(
      q.exits.map((e) => [e.id, e.state, e.requeuedFrom, e.requeuedTo]),
      [
        [3, "queued", undefined, []],
        [4, "queued", 1, []],
        [1, "requeued", undefined, [4]],
      ],
    );
  });

  it("refuses a requeue link to an exit queued no later than the one it came from", async () => {
    for (const link of [
      { requeued_from: 4 },
      { requeued_from: 5 },
      { requeued_to: [2] },
      { requeued_to: [1] },
      { requeued_to: ["4"] },
    ]) {
      await assert.rejects(
        queue([exit(3, "queued", 0), { ...exit(4, "queued", 1), ...link }]),
        isCode("indexer_fault"),
      );
    }
  });
});

describe("relayer client", () => {
  const proof = {
    a: "",
    b: "",
    c: "",
    root: "",
    public_amount: "",
    ext_data_hash: "",
    input_nullifiers: ["", ""] as [string, string],
    output_commitments: ["", ""] as [string, string],
  };
  const ext = {
    vault: "",
    network_id: "",
    deadline: 0,
    ext_amount: "0",
    fee: "0",
    recipient: "",
    relayer: "",
    encrypted_output0: "",
    encrypted_output1: "",
  };

  const HELD_ID = "0f".repeat(16);

  it("takes the hash of a submission, or the ID of one held until not_before", async () => {
    const hash = "ab".repeat(32);
    const sent = await new RelayerClient("http://r", reply(202, { hash })).submit(proof, ext);
    assert.deepEqual(sent, { accepted: true, hash, heldId: undefined });
    const held = new RelayerClient("http://r", reply(202, { held: true, id: HELD_ID }));
    assert.deepEqual(await held.submit(proof, ext, 1_800_000_000), {
      accepted: true,
      hash: undefined,
      heldId: HELD_ID,
    });
    // Only a delayed request may come back without a hash, and then with its ID.
    await assert.rejects(held.submit(proof, ext), isCode("service_rejected"));
    for (const body of [
      {},
      { held: true },
      { held: true, id: "0F".repeat(16) },
      { held: true, id: "0f" },
    ]) {
      await assert.rejects(
        new RelayerClient("http://r", reply(202, body)).submit(proof, ext, 1_800_000_000),
        isCode("service_rejected"),
      );
    }
  });

  it("reads every error code of a submission and the reason of a refusal", async () => {
    for (const error of [
      "bad_request",
      "wrong_vault",
      "fee_too_low",
      "fee_above_cap",
      "duplicate",
      "paused",
      "rejected",
      "rate_limited",
      "unavailable",
    ]) {
      const result = await new RelayerClient("http://r", reply(400, { error })).submit(proof, ext);
      assert.deepEqual(result, { accepted: false, error, reason: undefined });
    }
    const refused = await new RelayerClient(
      "http://r",
      reply(403, { error: "refused", reason: 1 }),
    ).submit(proof, ext);
    assert.deepEqual(refused, { accepted: false, error: "refused", reason: 1 });
    const odd = await new RelayerClient("http://r", reply(418, { error: "teapot" })).submit(
      proof,
      ext,
    );
    assert.deepEqual(odd, { accepted: false, error: "unknown", reason: undefined });
    await assert.rejects(
      new RelayerClient("http://r", reply(503, { error: "unavailable" })).quote(),
      (err: unknown) =>
        isCode("service_rejected")(err) && (err as CyphrasError).details["code"] === "unavailable",
    );
  });

  it("reads a transaction's status, with the code of a failure and the exit it queued", async () => {
    const hash = "aa".repeat(32);
    const tx = (status: number, body: unknown) =>
      new RelayerClient("http://r", reply(status, body)).tx(hash);
    assert.deepEqual(await tx(200, { status: "pending" }), {
      status: "pending",
      code: undefined,
      exitId: undefined,
    });
    assert.deepEqual(await tx(200, { status: "success", exit_id: 4 }), {
      status: "success",
      code: undefined,
      exitId: 4,
    });
    assert.deepEqual(await tx(200, { status: "failed", code: "rejected" }), {
      status: "failed",
      code: "rejected",
      exitId: undefined,
    });
    assert.equal(await tx(404, { error: "not_found" }), undefined);
    await assert.rejects(tx(200, { status: "lost" }), isCode("service_rejected"));
    await assert.rejects(tx(200, { status: "success", exit_id: 0 }), isCode("service_rejected"));
    await assert.rejects(tx(429, { error: "rate_limited" }), isCode("service_unavailable"));
  });

  it("follows a held request by its ID until it is sent or fails", async () => {
    const hash = "bb".repeat(32);
    const held = (status: number, body: unknown) =>
      new RelayerClient("http://r", reply(status, body)).held(HELD_ID);
    const none = { hash: undefined, code: undefined, reason: undefined, exitId: undefined };
    assert.deepEqual(await held(200, { status: "held" }), { ...none, status: "held" });
    assert.deepEqual(await held(200, { status: "pending", hash }), {
      ...none,
      status: "pending",
      hash,
    });
    assert.deepEqual(await held(200, { status: "success", hash, exit_id: 2 }), {
      ...none,
      status: "success",
      hash,
      exitId: 2,
    });
    // refused by the screening when it was due, so never sent
    assert.deepEqual(await held(200, { status: "failed", code: "refused", reason: 3 }), {
      ...none,
      status: "failed",
      code: "refused",
      reason: 3,
    });
    assert.deepEqual(await held(200, { status: "failed", hash, code: "rejected" }), {
      ...none,
      status: "failed",
      hash,
      code: "rejected",
    });
    // a relayer that restarted no longer knows the request
    assert.equal(await held(404, { error: "not_found" }), undefined);
    for (const body of [
      { status: "held", hash },
      { status: "pending" },
      { status: "success" },
      { status: "sent", hash },
      { status: "pending", hash: "BB".repeat(32) },
    ]) {
      await assert.rejects(held(200, body), isCode("service_rejected"));
    }
  });
});

describe("RPC client", () => {
  it("reports JSON-RPC errors by method and code only", async () => {
    const rpc = new SorobanRpc(
      "http://rpc",
      reply(200, { jsonrpc: "2.0", id: 1, error: { code: -32600, message: "secret detail" } }),
    );
    await assert.rejects(rpc.getLatestLedger(), (err: unknown) => {
      assert.ok(isCode("rpc_error")(err));
      assert.deepEqual((err as CyphrasError).details, { method: "getLatestLedger", code: -32600 });
      assert.ok(!(err as Error).message.includes("secret detail"));
      return true;
    });
  });

  it("reads the vault error of a failed simulation", async () => {
    const rpc = new SorobanRpc(
      "http://rpc",
      reply(200, {
        jsonrpc: "2.0",
        id: 1,
        result: { error: "HostError: Error(Contract, #42)", latestLedger: 5 },
      }),
    );
    const simulation = await rpc.simulateTransaction("AAAA");
    assert.equal(simulation.failed, true);
    assert.equal(simulation.contractError, 42);
  });
});
