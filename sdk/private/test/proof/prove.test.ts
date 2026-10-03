// Real Groth16 proofs of SDK-built transactions with the frozen circuit and a dev proving key, each
// verified against the verifying key exported from that same proving key. Needs the circuit build
// (cd circuits && npm ci && npm run compile) and a key at
// circuits/build/testnet-forgeable/transaction.zkey, which npm run setup:testnet-forgeable writes,
// or the paths in CYPHRAS_WASM and CYPHRAS_ZKEY.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { mnemonicToSeedSync } from "@scure/bip39";
import * as snarkjs from "snarkjs";
import { type ArtifactName, PinnedArtifacts } from "../../src/artifacts.ts";
import { computeDomain } from "../../src/domain.ts";
import { decryptIncoming } from "../../src/encryption.ts";
import { P } from "../../src/field.ts";
import { type TxProof, fromHostProof } from "../../src/extdata.ts";
import { parseVerifyingKey, verifyGroth16 } from "../../src/groth16.ts";
import { NETWORK_PASSPHRASES, defaultAddressKey, deriveSpendingKeys } from "../../src/keys.ts";
import { CommitmentTree, EMPTY_ROOT } from "../../src/merkle.ts";
import { snarkjsProver } from "@cyphras/private-prover-snarkjs";
import { type TransactionWitness, publicInputs } from "../../src/prover.ts";
import { proveTransaction } from "../../src/proving.ts";
import {
  type BuiltTransaction,
  type ExtTerms,
  type SpendNote,
  buildTransaction,
} from "../../src/transaction.ts";
import { utf8 } from "../../src/bytes.ts";
import { MNEMONIC, REPO_ROOT, fixture, testScalar } from "../helpers.ts";

const BUILD = join(REPO_ROOT, "circuits", "build");
const WASM = process.env["CYPHRAS_WASM"] ?? join(BUILD, "transaction_js", "transaction.wasm");
const ZKEY = process.env["CYPHRAS_ZKEY"] ?? join(BUILD, "testnet-forgeable", "transaction.zkey");

const FIXTURE = fixture<{ vault: string; accounts: Record<string, string> }>("vault-proofs.json");
const seed = mnemonicToSeedSync(MNEMONIC);
const alice = deriveSpendingKeys(seed, "testnet", 0);
const bob = deriveSpendingKeys(seed, "testnet", 1);
const aliceAddress = defaultAddressKey(alice);
const bobAddress = defaultAddressKey(bob);
const DOMAIN = computeDomain("testnet", "native");
const NETWORK_ID = new Uint8Array(
  createHash("sha256").update(NETWORK_PASSPHRASES.testnet).digest(),
);

function terms(extAmount: bigint, fee: bigint, recipient: string, relayer: string): ExtTerms {
  return {
    vault: FIXTURE.vault,
    networkId: NETWORK_ID,
    deadline: 10_000_000,
    extAmount,
    fee,
    recipient,
    relayer,
  };
}

const spendOf = (
  tx: BuiltTransaction,
  slot: number,
  pos: number,
  tree: CommitmentTree,
): SpendNote => {
  const out = tx.outputs[slot] as BuiltTransaction["outputs"][0];
  return { ...out.address, value: out.value, rcm: out.rcm, pos, path: tree.partialPath(pos) };
};

const snarkjsForm = (proof: TxProof): snarkjs.SnarkjsProof => {
  const p = fromHostProof(proof.proof);
  const s = (x: bigint): string => x.toString();
  return {
    pi_a: [s(p.a[0]), s(p.a[1]), "1"],
    pi_b: [
      [s(p.b[0][0]), s(p.b[0][1])],
      [s(p.b[1][0]), s(p.b[1][1])],
      ["1", "0"],
    ],
    pi_c: [s(p.c[0]), s(p.c[1]), "1"],
    protocol: "groth16",
    curve: "bn128",
  };
};

describe("proving with the frozen circuit", () => {
  const prover = snarkjsProver();
  let artifacts: PinnedArtifacts;
  let vkJson: unknown;
  const timings: number[] = [];

  before(async () => {
    for (const path of [WASM, ZKEY]) {
      if (!existsSync(path)) throw new Error(`missing an artifact at ${path}`);
    }
    // The verifying key comes from the proving key in use, and the pins are the files' own hashes,
    // so a freshly set up dev key works as well as the one the contracts pin.
    vkJson = await snarkjs.zKey.exportVerificationKey(new Uint8Array(readFileSync(ZKEY)));
    const files: Record<ArtifactName, Uint8Array> = {
      wasm: new Uint8Array(readFileSync(WASM)),
      zkey: new Uint8Array(readFileSync(ZKEY)),
      vkey: utf8(JSON.stringify(vkJson)),
    };
    const pins = Object.fromEntries(
      Object.entries(files).map(([name, bytes]) => [
        name,
        createHash("sha256").update(bytes).digest("hex"),
      ]),
    ) as Record<ArtifactName, string>;
    artifacts = new PinnedArtifacts({ load: async (name) => files[name] }, pins);
  });

  after(async () => {
    await prover.close();
  });

  async function prove(tx: BuiltTransaction, label: string): Promise<TxProof> {
    const start = performance.now();
    const proof = await proveTransaction(tx.witness, prover, artifacts);
    const ms = performance.now() - start;
    timings.push(ms);
    console.log(`# proved ${label} in ${(ms / 1000).toFixed(2)} s`);
    const vk = await artifacts.verifyingKey();
    const inputs = publicInputs(tx.witness);
    assert.ok(verifyGroth16(vk, fromHostProof(proof.proof), inputs));
    const signals = inputs.map((x) => x.toString());
    assert.ok(await snarkjs.groth16.verify(vkJson, signals, snarkjsForm(proof)));
    return proof;
  }

  it("loads the artifacts through their pins", async () => {
    await artifacts.proving();
    assert.deepEqual(await artifacts.verifyingKey(), parseVerifyingKey(vkJson));
  });

  let shield: BuiltTransaction;
  let transfer: BuiltTransaction;
  const tree = CommitmentTree.empty();
  const leaves: bigint[] = [];

  it("proves a shield: two dummies into the depositor's own notes", async () => {
    const depositor = FIXTURE.accounts["alice"] as string;
    shield = buildTransaction({
      keys: alice,
      self: aliceAddress,
      root: EMPTY_ROOT,
      domain: DOMAIN,
      inputs: [],
      outputs: [
        { address: aliceAddress, value: 1_000_000_000n },
        { address: aliceAddress, value: 0n },
      ],
      ext: terms(1_000_000_000n, 0n, depositor, depositor),
    });
    const proof = await prove(shield, "a shield");
    assert.equal(proof.publicAmount, 1_000_000_000n);
    assert.equal(proof.root, EMPTY_ROOT);
  });

  it("proves a relayed transfer of one real note and a dummy", async () => {
    for (let i = 0; i < 6; i++) leaves.push(testScalar("prove/leaf", i, P));
    leaves.push(...shield.commitments);
    tree.applyPage(leaves);
    const slot = shield.outputs.findIndex((o) => o.value > 0n);
    const funds = spendOf(shield, slot, 6 + slot, tree);
    const relayer = FIXTURE.accounts["relayer"] as string;
    transfer = buildTransaction({
      keys: alice,
      self: aliceAddress,
      root: tree.root(),
      domain: DOMAIN,
      inputs: [funds],
      outputs: [
        { address: bobAddress, value: 600_000_000n },
        { address: aliceAddress, value: 395_000_000n },
      ],
      ext: terms(0n, 5_000_000n, relayer, relayer),
    });
    await prove(transfer, "a transfer");
    const toBob = transfer.outputs.findIndex((o) => o.value === 600_000_000n);
    const ciphertext = toBob === 0 ? transfer.ext.encryptedOutput0 : transfer.ext.encryptedOutput1;
    const received = decryptIncoming(bob, transfer.commitments[toBob] as bigint, ciphertext);
    assert.equal(received?.value, 600_000_000n);
  });

  it("proves an unshield of two real notes to a muxed account", async () => {
    leaves.push(...transfer.commitments);
    tree.applyPage(leaves);
    const changeSlot = transfer.outputs.findIndex((o) => o.value === 395_000_000n);
    const second = buildTransaction({
      keys: alice,
      self: aliceAddress,
      root: EMPTY_ROOT,
      domain: DOMAIN,
      inputs: [],
      outputs: [
        { address: aliceAddress, value: 70_000_000n },
        { address: aliceAddress, value: 0n },
      ],
      ext: terms(
        70_000_000n,
        0n,
        FIXTURE.accounts["alice"] as string,
        FIXTURE.accounts["alice"] as string,
      ),
    });
    leaves.push(...second.commitments);
    tree.applyPage(leaves);
    const secondSlot = second.outputs.findIndex((o) => o.value > 0n);
    const inputs = [
      spendOf(transfer, changeSlot, 8 + changeSlot, tree),
      spendOf(second, secondSlot, 10 + secondSlot, tree),
    ];
    const unshield = buildTransaction({
      keys: alice,
      self: aliceAddress,
      root: tree.root(),
      domain: DOMAIN,
      inputs,
      outputs: [
        { address: aliceAddress, value: 55_000_000n },
        { address: aliceAddress, value: 0n },
      ],
      ext: terms(
        -400_000_000n,
        10_000_000n,
        FIXTURE.accounts["exchange_muxed"] as string,
        FIXTURE.accounts["relayer"] as string,
      ),
    });
    assert.equal(unshield.realSlots.length, 2);
    await prove(unshield, "an unshield with two real inputs");
  });

  it("refuses a witness the circuit does not satisfy", async () => {
    const broken: TransactionWitness = { ...shield.witness, inValue: [1n, 0n] };
    await assert.rejects(proveTransaction(broken, prover, artifacts), /failed/);
  });

  it("reports the proving time", () => {
    const mean = timings.reduce((a, b) => a + b, 0) / timings.length;
    console.log(`# mean proving time ${(mean / 1000).toFixed(2)} s over ${timings.length} proofs`);
    assert.ok(timings.length >= 3);
  });
});
