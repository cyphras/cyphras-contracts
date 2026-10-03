import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { describe, it } from "node:test";
import { xdr } from "@stellar/stellar-base";
import { bytesToHex, toHex32 } from "../../src/bytes.ts";
import { computeDomain } from "../../src/domain.ts";
import {
  type ExtDataJson,
  type TxProofJson,
  extDataFromJson,
  extDataHash,
  extDataToJson,
  extDataXdr,
  fromHostProof,
  publicAmount,
  toHostProof,
  txProofFromJson,
  txProofToJson,
  txProofToScVal,
} from "../../src/extdata.ts";
import { CommitmentTree, EMPTY_ROOT } from "../../src/merkle.ts";
import { fixture, wireProof } from "../helpers.ts";

// contracts/vault/fixtures/proofs.json of the contracts branch, which the vault's tests replay.
interface Step {
  name: string;
  call: "shield" | "transact" | "admit";
  ext?: ExtDataJson;
  ext_xdr?: string;
  proof?: TxProofJson & { domain: string };
  ids?: number[];
  root_after?: string;
}

interface VaultProofs {
  network_passphrase: string;
  network_id: string;
  vault: string;
  asset: string;
  domain: string;
  empty_root: string;
  steps: Step[];
  refused: Step[];
}

const PROOFS = fixture<VaultProofs>("vault-proofs.json");
const withExt = [...PROOFS.steps, ...PROOFS.refused].filter((s) => s.ext !== undefined);

describe("vault fixtures", () => {
  it("binds the testnet network, the native asset and the empty tree", () => {
    const networkId = createHash("sha256").update(PROOFS.network_passphrase).digest("hex");
    assert.equal(PROOFS.network_id, networkId);
    assert.equal(toHex32(computeDomain("testnet", PROOFS.asset)), PROOFS.domain);
    assert.equal(toHex32(EMPTY_ROOT), PROOFS.empty_root);
  });

  for (const step of withExt) {
    it(`encodes the ExtData of ${step.name} byte for byte`, () => {
      const ext = extDataFromJson(step.ext as ExtDataJson);
      assert.equal(bytesToHex(extDataXdr(ext)), step.ext_xdr);
      assert.deepEqual(extDataToJson(ext), step.ext);
      const proof = step.proof as TxProofJson;
      assert.equal(toHex32(extDataHash(ext)), proof.ext_data_hash);
      assert.equal(toHex32(publicAmount(ext.extAmount, ext.fee)), proof.public_amount);
    });
  }

  it("encodes TxProof as the vault's contracttype", () => {
    for (const step of withExt) {
      const { domain, ...json } = step.proof as TxProofJson & { domain: string };
      assert.equal(domain, PROOFS.domain);
      const proof = txProofFromJson(wireProof(json));
      assert.equal(toHex32(proof.root), json.root);
      assert.equal(toHex32(proof.inputNullifiers[1]), json.input_nullifiers[1]);
      assert.deepEqual(txProofToJson(proof), wireProof(json));
      assert.deepEqual(toHostProof(fromHostProof(proof.proof)), proof.proof);
      const decoded = xdr.ScVal.fromXDR(txProofToScVal(proof).toXDR());
      const keys = decoded.map()?.map((e) => e.key().sym().toString());
      assert.deepEqual(keys, [
        "ext_data_hash",
        "input_nullifiers",
        "output_commitments",
        "proof",
        "public_amount",
        "root",
      ]);
      const inner = decoded.map()?.find((e) => e.key().sym().toString() === "proof");
      const parts = inner
        ?.val()
        .map()
        ?.map((e) => [e.key().sym().toString(), e.val().bytes()]);
      assert.deepEqual(
        parts?.map(([k, v]) => [k, bytesToHex(Uint8Array.from(v as Uint8Array))]),
        [
          ["a", json.a],
          ["b", json.b],
          ["c", json.c],
        ],
      );
    }
  });

  it("builds the same tree as the vault through the fixture sequence", () => {
    const tree = CommitmentTree.empty();
    const leaves: bigint[] = [];
    const pending = new Map<string, [string, string]>();
    for (const step of PROOFS.steps) {
      if (step.call === "shield") {
        assert.equal(step.proof?.root, PROOFS.empty_root);
        pending.set(step.name, step.proof?.output_commitments as [string, string]);
        continue;
      }
      if (step.call === "admit") {
        for (const outputs of pending.values()) leaves.push(...outputs.map(BigInt));
      } else {
        assert.equal(toHex32(tree.root()), step.proof?.root);
        leaves.push(...(step.proof?.output_commitments ?? []).map(BigInt));
      }
      tree.applyPage(leaves);
      assert.equal(toHex32(tree.root()), step.root_after, step.name);
    }
  });
});
