import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, it } from "node:test";
import { CyphrasError } from "../../src/errors.ts";
import { P } from "../../src/field.ts";
import { Fields, type FetchLike } from "../../src/net/http.ts";
import { IndexerClient } from "../../src/net/indexer.ts";
import { RelayerClient } from "../../src/net/relayer.ts";
import { SorobanRpc } from "../../src/net/rpc.ts";
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
    assert.equal(vaultErrorName(4), "Halted");
    assert.equal(vaultErrorName(42), "DepositTooSmall");
    assert.equal(vaultErrorName(9999), undefined);
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
      cursor: null,
      complete_to_ledger: 10,
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
});

describe("relayer client", () => {
  it("reads error codes and refusal reasons", async () => {
    const relayer = new RelayerClient("http://r", reply(403, { error: "refused", reason: 1 }));
    const result = await relayer.submit(
      {
        a: "",
        b: "",
        c: "",
        root: "",
        public_amount: "",
        ext_data_hash: "",
        input_nullifiers: ["", ""],
        output_commitments: ["", ""],
      },
      {
        vault: "",
        network_id: "",
        deadline: 0,
        ext_amount: "0",
        fee: "0",
        recipient: "",
        relayer: "",
        encrypted_output0: "",
        encrypted_output1: "",
      },
    );
    assert.deepEqual(result, { accepted: false, error: "refused", reason: 1 });
    const odd = await new RelayerClient("http://r", reply(500, { error: "teapot" })).status(
      "aa".repeat(32),
    );
    assert.equal(odd, "unknown");
    await assert.rejects(
      new RelayerClient("http://r", reply(503, { error: "unavailable" })).quote(),
      (err: unknown) =>
        isCode("service_rejected")(err) && (err as CyphrasError).details["code"] === "unavailable",
    );
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
