import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, it } from "node:test";
import { SorobanRpc } from "../../src/net/rpc.ts";

// getTransaction as soroban-testnet.stellar.org answered it for two shields into the testnet vault
// CDV4V6W4MGMEVYYXENX2QXZCID7NT2UGAH2EWEBO3JUHO47Q27J7NTLL, both simulated against the same next
// deposit id and applied in ledger 5296872 on 2026-10-20 by an SDK without deposit room: one
// landed, and the other failed writing a Pending entry its footprint did not declare.
const RACE = JSON.parse(
  readFileSync(join(import.meta.dirname, "..", "fixtures", "testnet-shield-race.json"), "utf8"),
) as Record<"failed" | "landed", unknown>;

function rpcAnswering(body: unknown): SorobanRpc {
  return new SorobanRpc("https://rpc.invalid", async () => Response.json(body));
}

describe("getTransaction on a real shield race", () => {
  it("flags the deposit that lost the race as a storage conflict", async () => {
    const status = await rpcAnswering(RACE.failed).getTransaction(
      "e276447f5ac33285fa00ae28634c592563d70ea84bade5b982716669cdf9c7e7",
    );
    assert.equal(status.status, "FAILED");
    assert.equal(status.ledger, 5296872);
    assert.equal(status.diagnosed, true);
    assert.equal(status.conflict, true);
  });

  it("does not flag the deposit that landed in the same ledger", async () => {
    const status = await rpcAnswering(RACE.landed).getTransaction(
      "118aa7597bb46abc18880787cd3f6fb409b1999fedb4de1a4db5d591c959d555",
    );
    assert.equal(status.status, "SUCCESS");
    assert.equal(status.ledger, 5296872);
    assert.equal(status.conflict, false);
  });
});
