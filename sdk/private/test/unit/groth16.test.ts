import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, it } from "node:test";
import { type ArtifactName, PinnedArtifacts, loadCircuit, sha256Hex } from "../../src/artifacts.ts";
import { utf8 } from "../../src/bytes.ts";
import { CyphrasError } from "../../src/errors.ts";
import { type TxProofJson, fromHostProof, txProofFromJson } from "../../src/extdata.ts";
import { P } from "../../src/field.ts";
import { parseVerifyingKey, verifyGroth16 } from "../../src/groth16.ts";
import { REPO_ROOT, SDK_ROOT, fixture, wireProof } from "../helpers.ts";

const VK_FILE = join(SDK_ROOT, "test", "fixtures", "testnet-forgeable-vk.json");
const CONTRACT_VK = join(
  REPO_ROOT,
  "contracts",
  "verifier",
  "keys",
  "testnet-forgeable",
  "verification_key.json",
);
const VK_BYTES = readFileSync(VK_FILE);
// The SHA-256 of contracts/verifier/keys/testnet-forgeable/verification_key.json.
const VK_SHA256 = "526f5befc2ff836621cc6f2f181fa50de3318a6865d6eca2121c678a225e2b9c";

interface Step {
  name: string;
  proof?: TxProofJson & { domain: string };
}

const STEPS = [
  ...fixture<{ steps: Step[] }>("vault-proofs.json").steps,
  ...fixture<{ refused: Step[] }>("vault-proofs.json").refused,
].filter((s) => s.proof !== undefined);

function inputs(step: Step): bigint[] {
  const p = step.proof as TxProofJson & { domain: string };
  return [
    p.root,
    p.public_amount,
    p.ext_data_hash,
    p.domain,
    ...p.input_nullifiers,
    ...p.output_commitments,
  ].map(BigInt);
}

describe("Groth16 verification", () => {
  const vk = parseVerifyingKey(JSON.parse(VK_BYTES.toString("utf8")));

  it("uses the testnet-forgeable key of the contracts branch", () => {
    assert.equal(createHash("sha256").update(VK_BYTES).digest("hex"), VK_SHA256);
  });

  it(
    "is the verifying key the contract pins, byte for byte",
    { skip: existsSync(CONTRACT_VK) ? false : "the contracts tree is not in this checkout" },
    () => {
      assert.deepEqual(VK_BYTES, readFileSync(CONTRACT_VK));
    },
  );

  for (const step of STEPS) {
    it(`verifies the vault fixture proof of ${step.name}`, () => {
      const proof = fromHostProof(txProofFromJson(wireProof(step.proof as TxProofJson)).proof);
      assert.equal(verifyGroth16(vk, proof, inputs(step)), true);
    });
  }

  it("refuses a changed input, a swapped proof element and bad input ranges", () => {
    const step = STEPS[0] as Step;
    const proof = fromHostProof(txProofFromJson(wireProof(step.proof as TxProofJson)).proof);
    const good = inputs(step);
    good.forEach((_, i) => {
      const changed = [...good];
      changed[i] = ((changed[i] as bigint) + 1n) % P;
      assert.equal(verifyGroth16(vk, proof, changed), false, `input ${i}`);
    });
    assert.equal(verifyGroth16(vk, { ...proof, a: proof.c, c: proof.a }, good), false);
    assert.equal(verifyGroth16(vk, proof, good.slice(1)), false);
    assert.equal(verifyGroth16(vk, proof, [...good.slice(0, 7), P]), false);
    assert.equal(verifyGroth16(vk, { ...proof, a: [proof.a[0], proof.a[1] + 1n] }, good), false);
  });

  it("refuses a malformed key or one from a setup without phase 2", () => {
    const json = JSON.parse(VK_BYTES.toString("utf8")) as Record<string, unknown>;
    const bad = [
      { ...json, protocol: "plonk" },
      { ...json, nPublic: 7 },
      { ...json, IC: (json["IC"] as unknown[]).slice(1) },
      { ...json, vk_delta_2: json["vk_gamma_2"] },
      { ...json, vk_gamma_2: json["vk_delta_2"] },
      { ...json, vk_alpha_1: ["1", "3", "1"] },
    ];
    for (const key of bad) {
      assert.throws(
        () => parseVerifyingKey(key),
        (err: unknown) => err instanceof CyphrasError,
      );
    }
  });
});

describe("pinned artifacts", () => {
  const files: Record<ArtifactName, Uint8Array> = {
    wasm: utf8("wasm bytes"),
    zkey: utf8("zkey bytes"),
    vkey: VK_BYTES,
  };
  const loads: ArtifactName[] = [];
  const source = {
    async load(name: ArtifactName): Promise<Uint8Array> {
      loads.push(name);
      return files[name];
    },
  };
  const hex = (b: Uint8Array): string => createHash("sha256").update(b).digest("hex");

  it("hashes like node:crypto", async () => {
    assert.equal(await sha256Hex(files.wasm), hex(files.wasm));
  });

  it("returns the circuit's files once their hashes match, and caches the verifying key", async () => {
    const pins = { wasm: hex(files.wasm), zkey: hex(files.zkey), vkey: VK_SHA256 };
    assert.deepEqual(await loadCircuit(source, pins), { wasm: files.wasm, zkey: files.zkey });
    const artifacts = new PinnedArtifacts(source, pins);
    assert.deepEqual(artifacts.circuit, { wasm: pins.wasm, zkey: pins.zkey });
    await artifacts.verifyingKey();
    await artifacts.verifyingKey();
    assert.deepEqual(loads.sort(), ["vkey", "wasm", "zkey"]);
  });

  it("stops on a mismatch and reports both hashes", async () => {
    const expected = "00".repeat(32);
    await assert.rejects(
      loadCircuit(source, { wasm: hex(files.wasm), zkey: expected }),
      (err: unknown) => {
        assert.ok(err instanceof CyphrasError && err.code === "artifact_mismatch");
        assert.deepEqual(err.details, { artifact: "zkey", computed: hex(files.zkey), expected });
        assert.ok(err.message.includes(hex(files.zkey)) && err.message.includes(expected));
        return true;
      },
    );
  });

  it("refuses missing pins", () => {
    assert.throws(
      () => new PinnedArtifacts(source, { wasm: "", zkey: hex(files.zkey), vkey: VK_SHA256 }),
      (err: unknown) => err instanceof CyphrasError && err.code === "deployment_not_pinned",
    );
  });
});
