import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { CyphrasError } from "../../src/errors.ts";
import {
  type Deployment,
  PINNED_DEPLOYMENTS,
  checkDeployment,
  resolveDeployment,
} from "../../src/deployments.ts";
import { computeDomain } from "../../src/domain.ts";
import { NETWORK_PASSPHRASES } from "../../src/keys.ts";
import { createWorld } from "../support/network.ts";

const isCode = (code: string) => (err: unknown) => err instanceof CyphrasError && err.code === code;

describe("pinned deployments", () => {
  it("pins no v2 vault yet, and refuses to open either network", () => {
    assert.deepEqual(Object.keys(PINNED_DEPLOYMENTS).sort(), ["mainnet/xlm", "testnet/xlm"]);
    for (const name of ["mainnet/xlm", "testnet/xlm"] as const) {
      assert.equal(PINNED_DEPLOYMENTS[name], null);
      assert.throws(
        () => resolveDeployment(name, true),
        (err: unknown) => {
          assert.ok(isCode("deployment_not_pinned")(err));
          assert.match((err as Error).message, /not deployed/);
          return true;
        },
      );
    }
    assert.throws(
      () => resolveDeployment("devnet/xlm" as "mainnet/xlm", true),
      isCode("invalid_argument"),
    );
  });

  it("cannot be changed at run time", async () => {
    const { deployment } = await createWorld();
    const pins = PINNED_DEPLOYMENTS as Record<string, Deployment | null>;
    assert.ok(Object.isFrozen(PINNED_DEPLOYMENTS));
    assert.throws(() => {
      pins["testnet/xlm"] = deployment;
    }, TypeError);
    assert.throws(() => {
      pins["devnet/xlm"] = deployment;
    }, TypeError);
    assert.equal(PINNED_DEPLOYMENTS["testnet/xlm"], null);
  });

  it("takes an unpinned deployment only when asked to, and checks it", async () => {
    const { deployment } = await createWorld();
    assert.throws(() => resolveDeployment(deployment, false), isCode("deployment_not_pinned"));
    assert.equal(resolveDeployment(deployment, true), deployment);
    const bad: Deployment[] = [
      { ...deployment, networkPassphrase: "Public Global Stellar Network ; September 2015" },
      { ...deployment, domain: deployment.domain + 1n },
      { ...deployment, vault: "GBXXXX" },
      { ...deployment, vaultWasmHash: "ABC" },
      { ...deployment, artifacts: { ...deployment.artifacts, zkey: "" } },
      { ...deployment, indexers: [] },
      { ...deployment, indexers: ["ftp://indexer"] },
      { ...deployment, indexers: ["https://user:pass@indexer.example"] },
      { ...deployment, feeTier: 0n },
    ];
    for (const d of bad) assert.throws(() => resolveDeployment(d, true), CyphrasError);
  });

  it("requires TLS for pinned services", async () => {
    const { deployment } = await createWorld();
    assert.throws(() => checkDeployment(deployment, true), isCode("invalid_argument"));
    const tls = {
      ...deployment,
      indexers: ["https://indexer.example"],
      relayers: [
        {
          ...(deployment.relayers[0] as Deployment["relayers"][0]),
          url: "https://relayer.example",
        },
      ],
    };
    assert.doesNotThrow(() => checkDeployment(tls, true));
  });

  it("requires a pinned mainnet deployment to recommend a second RPC provider", async () => {
    const { deployment } = await createWorld();
    const mainnet: Deployment = {
      ...deployment,
      network: "mainnet",
      networkPassphrase: NETWORK_PASSPHRASES.mainnet,
      domain: computeDomain("mainnet", deployment.asset.name),
      indexers: ["https://indexer.example"],
      relayers: [
        {
          url: "https://relayer.example",
          feeAddress: deployment.relayers[0]?.feeAddress as string,
        },
      ],
    };
    assert.throws(() => checkDeployment(mainnet, true), isCode("invalid_argument"));
    assert.doesNotThrow(() => checkDeployment({ ...mainnet, recommendSecondRpc: true }, true));
    assert.doesNotThrow(() => checkDeployment(mainnet, false));
  });
});
