import { createHash } from "node:crypto";
import { P, packPoint } from "./babyjub.mjs";
import {
  TAG,
  addressAt,
  bip39Seed,
  defaultAddress,
  deriveKeys,
  diversifier,
  fold,
  fullViewingKey,
  incomingViewingKey,
} from "./keys.mjs";
import { LEVELS, MerkleTree, ZEROS, addressFold, noteCommitment, nullifier } from "./notes.mjs";

export const MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

const FORMAT =
  "Field elements and scalars are 0x-prefixed 32-byte big-endian hex. Byte strings are " +
  "unprefixed hex. Points are affine Baby Jubjub coordinates; packed points use packPoint.";

const hex32 = (x) => "0x" + x.toString(16).padStart(64, "0");
const bytes = (b) => Buffer.from(b).toString("hex");
const point = (p) => ({ x: hex32(p[0]), y: hex32(p[1]) });

export function keyVectors() {
  const seed = bip39Seed(MNEMONIC);
  const accounts = [];
  for (const network of ["mainnet", "testnet"]) {
    for (const account of [0, 1]) {
      const k = deriveKeys(seed, network, account);
      const diversifiers = [0, 1, 2].map((index) => {
        const a = addressAt(k, index);
        if (a === null) return { index, d: bytes(diversifier(k.dk, index)), valid: false };
        return {
          index,
          d: bytes(a.d),
          valid: true,
          q: point(a.q),
          g_d: point(a.gd),
          pk_d: point(a.pkd),
          pk_d_packed: bytes(packPoint(a.pkd)),
          address: a.address,
        };
      });
      accounts.push({
        network,
        account,
        ask: hex32(k.ask),
        nsk: hex32(k.nsk),
        ovk: bytes(k.ovk),
        dk: bytes(k.dk),
        ak: point(k.ak),
        ak_packed: bytes(packPoint(k.ak)),
        nk: point(k.nk),
        nk_packed: bytes(packPoint(k.nk)),
        ak_fold: hex32(k.akFold),
        nk_fold: hex32(k.nkFold),
        ivk: hex32(k.ivk),
        diversifiers,
        default_address_index: defaultAddress(k).index,
        incoming_viewing_key: incomingViewingKey(k),
        full_viewing_key: fullViewingKey(k),
      });
    }
  }
  return {
    description: "Shielded key, diversified address and viewing key vectors.",
    format: FORMAT,
    mnemonic: MNEMONIC,
    passphrase: "",
    seed: bytes(seed),
    accounts,
  };
}

// rcm values are derived, not random, so the file regenerates byte for byte.
const vectorRcm = (i) =>
  BigInt("0x" + createHash("sha512").update(`cyphras/v2/vectors/rcm/${i}`).digest("hex")) % P;

const NOTE_CASES = [
  { value: 0n, rcm: 0, pos: 0 },
  { value: 1n, rcm: 1, pos: 1 },
  { value: 250_000_000n, rcm: 2, pos: 1234 },
  { value: 250_000_000n, rcm: 2, pos: 1235 },
  { value: (1n << 64n) - 1n, rcm: 3, pos: 2 ** LEVELS - 1 },
];

export function noteVectors() {
  const owner = deriveKeys(bip39Seed(MNEMONIC), "mainnet", 0);
  const address = defaultAddress(owner);
  const notes = NOTE_CASES.map(({ value, rcm, pos }) => {
    const n = { value, gd: address.gd, pkd: address.pkd, rcm: vectorRcm(rcm) };
    const cm = noteCommitment(n);
    return {
      value: value.toString(),
      g_d: point(n.gd),
      pk_d: point(n.pkd),
      rcm: hex32(n.rcm),
      g_d_fold: hex32(fold(n.gd, TAG.gd)),
      pk_d_fold: hex32(fold(n.pkd, TAG.pkd)),
      address_fold: hex32(addressFold(n.gd, n.pkd)),
      cm: hex32(cm),
      pos,
      nf: hex32(nullifier(cm, pos, owner.nkFold)),
    };
  });

  const tree = new MerkleTree();
  const leaves = [...new Set(notes.map((n) => n.cm))].map(BigInt);
  const roots = leaves.map((leaf, i) => {
    tree.set(i, leaf);
    return hex32(tree.root());
  });

  return {
    description: "Note commitment, nullifier and Merkle tree vectors.",
    format: FORMAT,
    owner: {
      mnemonic: MNEMONIC,
      network: "mainnet",
      account: 0,
      diversifier_index: address.index,
      nk_fold: hex32(owner.nkFold),
    },
    rcm_derivation: 'rcm_i = SHA-512("cyphras/v2/vectors/rcm/" || i) mod p, for these vectors only',
    notes,
    merkle: {
      levels: LEVELS,
      zeros: ZEROS.map(hex32),
      leaves: leaves.map(hex32),
      roots_after_each_insert: roots,
    },
  };
}
