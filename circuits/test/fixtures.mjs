import { randomBytes } from "node:crypto";
import { BASE8, F, L, mul } from "../reference/babyjub.mjs";
import { hash } from "../reference/poseidon2.mjs";
import { TAG, bip39Seed, defaultAddress, deriveKeys, fold } from "../reference/keys.mjs";
import { LEVELS, MerkleTree, noteCommitment, nullifier } from "../reference/notes.mjs";
import { MNEMONIC } from "../reference/vectors.mjs";
import { randomField } from "./helpers.mjs";

export const MAX_VALUE = (1n << 64n) - 1n;
export const MAX_POS = (1n << BigInt(LEVELS)) - 1n;

const SEED = bip39Seed(MNEMONIC);

function wallet(account) {
  const keys = deriveKeys(SEED, "testnet", account);
  return { keys, address: defaultAddress(keys) };
}

export function note(value, address, rcm = randomField()) {
  return { value: BigInt(value), gd: address.gd, q: address.q, pkd: address.pkd, rcm };
}

const randomPos = () => BigInt(randomBytes(4).readUInt32LE()) & MAX_POS;

export function spend(owner, n, pos, pathElements) {
  return {
    value: n.value,
    ask: owner.keys.ask,
    nsk: owner.keys.nsk,
    gd: n.gd,
    q: n.q,
    rcm: n.rcm,
    pos: BigInt(pos),
    pathElements,
  };
}

export const randomPath = () => Array.from({ length: LEVELS }, randomField);

export function dummy(owner) {
  return spend(owner, note(0n, owner.address), randomPos(), randomPath());
}

// What the circuit derives from one input's witness, so a tampered witness still carries the
// nullifier the circuit itself would compute and fails only on the defense under test.
export function spendView({ value, ask, nsk, gd, rcm, pos }) {
  const nkFold = fold(mul(BASE8, nsk), TAG.nk);
  const ivk = hash([fold(mul(BASE8, ask), TAG.ak), nkFold], TAG.ivk) % L;
  const pkd = mul(gd, ivk);
  const cm = noteCommitment({ value, gd, pkd, rcm });
  return { pkd, cm, nf: nullifier(cm, pos, nkFold) };
}

export function transactionInput({ root, publicAmount, extDataHash, domain, spends, outputs }) {
  return {
    root,
    publicAmount: F.e(publicAmount),
    extDataHash,
    domain,
    nf: spends.map((s) => spendView(s).nf),
    cmOut: outputs.map(noteCommitment),
    inValue: spends.map((s) => s.value),
    inAsk: spends.map((s) => s.ask),
    inNsk: spends.map((s) => s.nsk),
    inGd: spends.map((s) => s.gd),
    inQ: spends.map((s) => s.q),
    inRcm: spends.map((s) => s.rcm),
    inPos: spends.map((s) => s.pos),
    inPathElements: spends.map((s) => s.pathElements),
    outValue: outputs.map((o) => o.value),
    outGd: outputs.map((o) => o.gd),
    outPkd: outputs.map((o) => o.pkd),
    outRcm: outputs.map((o) => o.rcm),
  };
}

export const PUBLIC_SIGNALS = [
  "root",
  "publicAmount",
  "extDataHash",
  "domain",
  "nf[0]",
  "nf[1]",
  "cmOut[0]",
  "cmOut[1]",
];

// A tree with unrelated leaves around the notes under test, so paths are not all zero hashes.
export function populatedTree(notes) {
  const tree = new MerkleTree();
  for (let pos = 0n; pos < 12n; pos++) tree.set(pos, randomField());
  for (const [pos, n] of notes) tree.set(pos, noteCommitment(n));
  return tree;
}

export function scenario(spends, outputs, publicAmount, tree) {
  return {
    root: tree.root(),
    publicAmount,
    extDataHash: randomField(),
    domain: randomField(),
    spends,
    outputs,
  };
}

export const alice = wallet(0);
export const bob = wallet(1);

export function shield(value = 250_000_000n) {
  const outputs = [note(value, alice.address), note(0n, alice.address)];
  return scenario([dummy(alice), dummy(alice)], outputs, value, populatedTree([]));
}

export function transfer(pos = 5n) {
  const funds = note(1_000_000_000n, alice.address);
  const tree = populatedTree([[pos, funds]]);
  const outputs = [note(600_000_000n, bob.address), note(400_000_000n, alice.address)];
  return scenario([spend(alice, funds, pos, tree.path(pos)), dummy(alice)], outputs, 0n, tree);
}

export function twoInputs() {
  const a = note(700_000_000n, alice.address);
  const b = note(300_000_000n, alice.address);
  const tree = populatedTree([
    [3n, a],
    [9n, b],
  ]);
  const spends = [spend(alice, a, 3n, tree.path(3n)), spend(alice, b, 9n, tree.path(9n))];
  const outputs = [note(900_000_000n, bob.address), note(100_000_000n, alice.address)];
  return scenario(spends, outputs, 0n, tree);
}

export function unshield(amount = 750_000_000n, fee = 5_000_000n) {
  const funds = note(1_000_000_000n, alice.address);
  const tree = populatedTree([[7n, funds]]);
  const outputs = [note(1_000_000_000n - amount - fee, alice.address), note(0n, alice.address)];
  const spends = [spend(alice, funds, 7n, tree.path(7n)), dummy(alice)];
  return scenario(spends, outputs, -(amount + fee), tree);
}
