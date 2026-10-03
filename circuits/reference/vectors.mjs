import { createHash } from "node:crypto";
import { bech32, bech32m } from "@scure/base";
import { A, D, F, GENERATOR, IDENTITY, L, P, add, mul, packPoint } from "./babyjub.mjs";
import {
  HRP,
  TAG,
  UNPROVABLE_SCALARS,
  VERSION,
  addressAt,
  bip39Seed,
  defaultAddress,
  deriveKeys,
  diversifier,
  fold,
  fullViewingKey,
  incomingViewingKey,
  toLE32,
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
        sk: bytes(k.sk),
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
    unprovable_scalars: UNPROVABLE_SCALARS.map(hex32),
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

// The smallest y with no point (x, y) on the curve.
function offCurveY() {
  for (let y = 2n; ; y++) {
    const y2 = F.square(y);
    if (F.sqrt(F.div(F.sub(1n, y2), F.sub(A, F.mul(D, y2)))) === null) return y;
  }
}

// packPoint with y replaced by y + p, a second encoding of the same point.
function packedPlusP(p) {
  const bytes = toLE32(p[1] + P);
  bytes[31] |= packPoint(p)[31] & 0x80;
  return bytes;
}

export function invalidEncodingVectors() {
  const seed = bip39Seed(MNEMONIC);
  const keys = deriveKeys(seed, "mainnet", 0);
  const testnet = deriveKeys(seed, "testnet", 0);
  const a = defaultAddress(keys);
  const t8 = mul(GENERATOR, L);
  const offCurve = toLE32(offCurveY());
  const negativeZero = packPoint(IDENTITY).map((b, i) => (i === 31 ? b | 0x80 : b));

  const addr = [VERSION, ...a.d, ...packPoint(a.pkd)];
  const ivk = [VERSION, ...keys.dk, ...toLE32(keys.ivk)];
  const fvk = [VERSION, ...packPoint(keys.ak), ...packPoint(keys.nk), ...keys.ovk, ...keys.dk];
  const splice = (payload, at, bytes) => [
    ...payload.slice(0, at),
    ...bytes,
    ...payload.slice(at + 32),
  ];
  const version = (payload, v) => [v, ...payload.slice(1)];
  const encode = (hrp, payload, limit) =>
    bech32m.encode(hrp, bech32m.toWords(Uint8Array.from(payload)), limit);
  const address = (payload) => encode(HRP.mainnet.address, payload, 90);
  const ivkKey = (payload) => encode(HRP.mainnet.ivk, payload, false);
  const fvkKey = (payload) => encode(HRP.mainnet.fvk, payload, false);
  const pkd = (bytes) => address(splice(addr, 12, bytes));
  const vector = (rule, reason, encoding, network = "mainnet") => ({
    network,
    encoding,
    rule,
    reason,
  });
  const bech32Checksum = bech32.encode(HRP.mainnet.address, bech32.toWords(Uint8Array.from(addr)));

  return {
    description: "Encodings a decoder MUST reject, with the rule each one breaks.",
    rules: {
      hrp: "an HRP other than the given network's",
      version: "a version byte other than 0x02",
      length: "a payload of the wrong length (44, 65 or 129 bytes)",
      bech32m: "a string that is not valid bech32m",
      point: "bytes that are not the canonical packPoint encoding of a curve point",
      identity: "the identity point",
      subgroup: "a point outside the prime-order subgroup",
      ivk_range: "an incoming viewing key not reduced mod L",
    },
    untestable: [
      "a d for which DiversifyHash fails: none is known, as one occurs with probability about 2^-256",
    ],
    address: [
      vector("hrp", "a testnet address", defaultAddress(testnet).address),
      vector("hrp", "a mainnet address", a.address, "testnet"),
      vector("version", "version 0x00 with 33 bytes", address([0x00, ...packPoint(a.pkd)])),
      vector("version", "version 0x01", address(version(addr, 0x01))),
      vector("version", "version 0x03", address(version(addr, 0x03))),
      vector("length", "43 bytes", address(addr.slice(0, 43))),
      vector("length", "45 bytes", address([...addr, 0])),
      vector("bech32m", "a bech32 checksum instead of bech32m", bech32Checksum),
      vector("bech32m", "mixed case", a.address.slice(0, 10) + a.address.slice(10).toUpperCase()),
      vector("point", "pk_d with no point at that y", pkd(offCurve)),
      vector("point", "pk_d encoded with y + p", pkd(packedPlusP(a.pkd))),
      vector("point", "pk_d = (0, 1) with the sign bit set", pkd(negativeZero)),
      vector("identity", "pk_d = (0, 1)", pkd(packPoint(IDENTITY))),
      vector("subgroup", "pk_d of order 2", pkd(packPoint(mul(t8, 4n)))),
      vector("subgroup", "pk_d of order 8", pkd(packPoint(t8))),
      vector("subgroup", "pk_d of order 8L", pkd(packPoint(add(a.pkd, t8)))),
    ],
    incoming_viewing_key: [
      vector("hrp", "a testnet key", incomingViewingKey(testnet)),
      vector("version", "version 0x01", ivkKey(version(ivk, 0x01))),
      vector("length", "64 bytes", ivkKey(ivk.slice(0, 64))),
      vector("length", "66 bytes", ivkKey([...ivk, 0])),
      vector("ivk_range", "ivk + L", ivkKey(splice(ivk, 33, toLE32(keys.ivk + L)))),
    ],
    full_viewing_key: [
      vector("hrp", "a testnet key", fullViewingKey(testnet)),
      vector("version", "version 0x01", fvkKey(version(fvk, 0x01))),
      vector("length", "128 bytes", fvkKey(fvk.slice(0, 128))),
      vector("point", "ak with no point at that y", fvkKey(splice(fvk, 1, offCurve))),
      vector("point", "ak encoded with y + p", fvkKey(splice(fvk, 1, packedPlusP(keys.ak)))),
      vector("identity", "nk = (0, 1)", fvkKey(splice(fvk, 33, packPoint(IDENTITY)))),
      vector("subgroup", "ak of order 8L", fvkKey(splice(fvk, 1, packPoint(add(keys.ak, t8))))),
    ],
  };
}
