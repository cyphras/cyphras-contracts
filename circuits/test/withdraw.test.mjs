import { expect } from "chai";
import { buildPoseidon } from "circomlibjs";
import * as snarkjs from "snarkjs";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const BUILD = join(here, "..", "build");
const WASM = join(BUILD, "withdraw_js", "withdraw.wasm");
const ZKEY = join(BUILD, "withdraw_final.zkey");
const VKEY = JSON.parse(readFileSync(join(BUILD, "verification_key.json"), "utf-8"));

const LEVELS = 20;

// public signal positions (must match the circuit's public input order)
const P_ROOT = 0;
const P_NULLIFIER_HASH = 1;
const P_RECIPIENT = 2;
const P_RELAYER = 3;
const P_RELAYER_FEE = 4;
const P_AMOUNT_HASH = 5;
const P_ASSET_ID = 6;

let poseidon;
let F;

function hash(values) {
  return F.toObject(poseidon(values));
}

function random31() {
  let hex = "";
  for (let i = 0; i < 31; i++) {
    hex += Math.floor(Math.random() * 256)
      .toString(16)
      .padStart(2, "0");
  }
  return BigInt("0x" + hex);
}

function buildNote(overrides = {}) {
  const secret = random31();
  const nullifier = random31();
  const amountBlinding = random31();
  const amount = overrides.amount ?? 1000000n;
  const relayerFee = overrides.relayerFee ?? 100000n;
  const assetId = 123456789012345678901234567890n;

  const nullifierHash = hash([nullifier, secret]);
  const amountHash = hash([amount, relayerFee, amountBlinding]);
  const commitment = hash([nullifier, secret, amountHash, assetId]);

  return {
    secret,
    nullifier,
    amountBlinding,
    amount,
    relayerFee,
    assetId,
    nullifierHash,
    amountHash,
    commitment,
  };
}

function buildPath(leaf) {
  const pathElements = [];
  const pathIndices = [];
  let current = leaf;
  for (let i = 0; i < LEVELS; i++) {
    const sibling = hash([BigInt(i + 1), BigInt(i * 7 + 3)]);
    const index = i % 2;
    pathElements.push(sibling);
    pathIndices.push(index);
    current = index === 0 ? hash([current, sibling]) : hash([sibling, current]);
  }
  return { pathElements, pathIndices, root: current };
}

function makeInput(note, path) {
  return {
    secret: note.secret.toString(),
    nullifier: note.nullifier.toString(),
    amount: note.amount.toString(),
    relayerFee: note.relayerFee.toString(),
    amountBlinding: note.amountBlinding.toString(),
    pathElements: path.pathElements.map((x) => x.toString()),
    pathIndices: path.pathIndices.map((x) => x.toString()),
    root: path.root.toString(),
    nullifierHash: note.nullifierHash.toString(),
    recipient: "1234567890",
    relayer: "9876543210",
    amountHash: note.amountHash.toString(),
    assetId: note.assetId.toString(),
  };
}

async function prove(input) {
  return snarkjs.groth16.fullProve(input, WASM, ZKEY);
}

async function expectWitnessRejected(input) {
  let threw = false;
  try {
    await prove(input);
  } catch {
    threw = true;
  }
  expect(threw).to.equal(true);
}

// Generates a valid proof, bumps one public signal by 1, and expects verification to
// fail - this is what actually binds recipient/relayer/relayerFee to the proof.
async function expectVerifyFailsWhenSignalTampered(index) {
  const note = buildNote();
  const path = buildPath(note.commitment);
  const { proof, publicSignals } = await prove(makeInput(note, path));
  const tampered = [...publicSignals];
  tampered[index] = (BigInt(tampered[index]) + 1n).toString();
  const ok = await snarkjs.groth16.verify(VKEY, tampered, proof);
  expect(ok).to.equal(false);
}

describe("withdraw circuit", function () {
  before(async () => {
    poseidon = await buildPoseidon();
    F = poseidon.F;
  });

  it("verifies a valid proof", async () => {
    const note = buildNote();
    const path = buildPath(note.commitment);
    const { proof, publicSignals } = await prove(makeInput(note, path));
    expect(await snarkjs.groth16.verify(VKEY, publicSignals, proof)).to.equal(true);
  });

  it("exposes exactly the 7 expected public signals in order", async () => {
    const note = buildNote();
    const path = buildPath(note.commitment);
    const { publicSignals } = await prove(makeInput(note, path));
    expect(publicSignals.length).to.equal(7);
    expect(publicSignals[P_ROOT]).to.equal(path.root.toString());
    expect(publicSignals[P_NULLIFIER_HASH]).to.equal(note.nullifierHash.toString());
    expect(publicSignals[P_RELAYER_FEE]).to.equal(note.relayerFee.toString());
    expect(publicSignals[P_AMOUNT_HASH]).to.equal(note.amountHash.toString());
    expect(publicSignals[P_ASSET_ID]).to.equal(note.assetId.toString());
  });

  it("verify fails if recipient is swapped after proving", async () => {
    await expectVerifyFailsWhenSignalTampered(P_RECIPIENT);
  });

  it("verify fails if relayer is swapped after proving", async () => {
    await expectVerifyFailsWhenSignalTampered(P_RELAYER);
  });

  it("verify fails if relayerFee is swapped after proving", async () => {
    await expectVerifyFailsWhenSignalTampered(P_RELAYER_FEE);
  });

  it("rejects a wrong nullifierHash", async () => {
    const note = buildNote();
    const path = buildPath(note.commitment);
    const input = makeInput(note, path);
    input.nullifierHash = (BigInt(input.nullifierHash) + 1n).toString();
    await expectWitnessRejected(input);
  });

  it("rejects a commitment not in the tree", async () => {
    const note = buildNote();
    const path = buildPath(note.commitment);
    const input = makeInput(note, path);
    input.root = (BigInt(input.root) + 1n).toString();
    await expectWitnessRejected(input);
  });

  it("rejects a tampered amountHash", async () => {
    const note = buildNote();
    const path = buildPath(note.commitment);
    const input = makeInput(note, path);
    input.amountHash = (BigInt(input.amountHash) + 1n).toString();
    await expectWitnessRejected(input);
  });

  it("rejects a tampered assetId", async () => {
    const note = buildNote();
    const path = buildPath(note.commitment);
    const input = makeInput(note, path);
    input.assetId = (BigInt(input.assetId) + 1n).toString();
    await expectWitnessRejected(input);
  });

  it("rejects an out-of-range pathIndices value", async () => {
    const note = buildNote();
    const path = buildPath(note.commitment);
    const input = makeInput(note, path);
    input.pathIndices[0] = "2";
    await expectWitnessRejected(input);
  });

  it("rejects an amount that exceeds 64 bits", async () => {
    const note = buildNote({ amount: 2n ** 64n });
    const path = buildPath(note.commitment);
    await expectWitnessRejected(makeInput(note, path));
  });

  it("rejects a relayerFee that exceeds 64 bits", async () => {
    const note = buildNote({ relayerFee: 2n ** 64n });
    const path = buildPath(note.commitment);
    await expectWitnessRejected(makeInput(note, path));
  });
});
