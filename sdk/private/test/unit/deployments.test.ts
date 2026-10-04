import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
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
import { REPO_ROOT, readJson } from "../helpers.ts";
import { createWorld } from "../support/network.ts";

const isCode = (code: string) => (err: unknown) => err instanceof CyphrasError && err.code === code;

// The part of deployments/<network>.json the pins are taken from.
interface DeploymentFile {
  network: string;
  network_passphrase: string;
  vaults: {
    asset: string;
    vault: string;
    token: string;
    deploy_ledger: number;
    fee_tier: string;
    urls: { indexer: string; relayer: string; screening: string };
    domain: string;
    wasm_hash: string;
    verifying_key: string;
    artifacts: { wasm: string; zkey: string; vkey: string };
    relayer_fee_address: string;
  }[];
}

const testnetPin = (): Deployment => {
  const pinned = PINNED_DEPLOYMENTS["testnet/xlm"];
  assert.ok(pinned !== null);
  return pinned;
};

describe("pinned deployments", () => {
  it("pins the testnet XLM vault, and refuses mainnet until a vault is deployed there", () => {
    assert.deepEqual(Object.keys(PINNED_DEPLOYMENTS).sort(), ["mainnet/xlm", "testnet/xlm"]);
    assert.equal(PINNED_DEPLOYMENTS["mainnet/xlm"], null);
    assert.throws(
      () => resolveDeployment("mainnet/xlm", true),
      (err: unknown) => {
        assert.ok(isCode("deployment_not_pinned")(err));
        assert.match((err as Error).message, /not deployed/);
        return true;
      },
    );
    const pinned = testnetPin();
    assert.doesNotThrow(() => checkDeployment(pinned, true));
    assert.equal(resolveDeployment("testnet/xlm", false), pinned);
    assert.throws(
      () => resolveDeployment("devnet/xlm" as "mainnet/xlm", true),
      isCode("invalid_argument"),
    );
  });

  it("pins the testnet XLM vault as deployments/testnet.json records it", () => {
    const file = readJson<DeploymentFile>(join(REPO_ROOT, "deployments", "testnet.json"));
    const vaults = file.vaults.filter((v) => v.asset === "native");
    assert.equal(vaults.length, 1);
    const v = vaults[0] as DeploymentFile["vaults"][0];
    const pinned = testnetPin();
    assert.equal(pinned.network, file.network);
    assert.equal(pinned.networkPassphrase, file.network_passphrase);
    assert.equal(pinned.vault, v.vault);
    assert.deepEqual(pinned.asset, { contract: v.token, name: v.asset });
    assert.equal(pinned.domain, BigInt(v.domain));
    assert.equal(pinned.domain, computeDomain("testnet", "native"));
    assert.equal(pinned.deployLedger, v.deploy_ledger);
    assert.equal(pinned.vaultWasmHash, v.wasm_hash);
    assert.deepEqual(pinned.artifacts, v.artifacts);
    assert.deepEqual(pinned.indexers, [v.urls.indexer]);
    assert.deepEqual(pinned.relayers, [{ url: v.urls.relayer, feeAddress: v.relayer_fee_address }]);
    assert.equal(pinned.feeTier, BigInt(v.fee_tier));
    // The verifying key pin is the key the vault's verifier was built with, hashed here again.
    const key = readFileSync(
      join(REPO_ROOT, "contracts", "verifier", "keys", v.verifying_key, "verification_key.json"),
    );
    assert.equal(createHash("sha256").update(key).digest("hex"), pinned.artifacts.vkey);
  });

  it("cannot be changed at run time", async () => {
    const { deployment } = await createWorld();
    const pins = PINNED_DEPLOYMENTS as Record<string, Deployment | null>;
    const pinned = testnetPin();
    assert.ok(Object.isFrozen(PINNED_DEPLOYMENTS));
    assert.throws(() => {
      pins["testnet/xlm"] = deployment;
    }, TypeError);
    assert.throws(() => {
      pins["devnet/xlm"] = deployment;
    }, TypeError);
    assert.equal(PINNED_DEPLOYMENTS["testnet/xlm"], pinned);
    const before = JSON.stringify(pinned, (_, v) => (typeof v === "bigint" ? v.toString() : v));
    const loose = pinned as unknown as {
      vault: string;
      artifacts: Record<string, string>;
      relayers: { url: string; feeAddress: string }[];
    };
    const relayer = loose.relayers[0] as { url: string; feeAddress: string };
    assert.throws(() => {
      loose.vault = deployment.vault;
    }, TypeError);
    assert.throws(() => {
      loose.artifacts["zkey"] = deployment.artifacts.zkey;
    }, TypeError);
    assert.throws(() => {
      loose.relayers.push({ url: "https://relayer.example", feeAddress: relayer.feeAddress });
    }, TypeError);
    assert.throws(() => {
      relayer.feeAddress = deployment.vault;
    }, TypeError);
    assert.equal(
      JSON.stringify(pinned, (_, v) => (typeof v === "bigint" ? v.toString() : v)),
      before,
    );
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
