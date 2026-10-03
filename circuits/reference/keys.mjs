import { createHmac, hkdfSync, pbkdf2Sync } from "node:crypto";
import { bech32m } from "@scure/base";
import { A, BASE8, D, F, L, isIdentity, mul, packPoint, timesCofactor } from "./babyjub.mjs";
import { hash } from "./poseidon2.mjs";

export const TAG = {
  commitment: 0x01,
  nullifier: 0x02,
  pkd: 0x05,
  nk: 0x06,
  ak: 0x07,
  gd: 0x08,
  address: 0x09,
  ivk: 0x10,
  diversify: 0x12,
};

const VERSION = 0x02;
const HRP = {
  mainnet: { address: "cy", ivk: "cyivk", fvk: "cyfvk" },
  testnet: { address: "cyt", ivk: "cytivk", fvk: "cytfvk" },
};

export const fold = (p, tag) => hash([p[0], p[1]], tag);

const os2ip = (bytes) => BigInt("0x" + Buffer.from(bytes).toString("hex"));
const fromLE = (bytes) => os2ip(Buffer.from(bytes).reverse());

function toLE32(x) {
  const out = Buffer.alloc(32);
  out.write(x.toString(16).padStart(64, "0"), "hex");
  return out.reverse();
}

export function bip39Seed(mnemonic, passphrase = "") {
  const salt = "mnemonic" + passphrase.normalize("NFKD");
  return pbkdf2Sync(mnemonic.normalize("NFKD"), salt, 2048, 64, "sha512");
}

function okm(seed, network, account, label) {
  const info = `${network}/${account}/${label}`;
  return Buffer.from(hkdfSync("sha512", seed, "cyphras/v2/shielded", info, 64));
}

function scalar(seed, network, account, label) {
  for (let retry = 0; ; retry++) {
    const s = os2ip(okm(seed, network, account, retry ? `${label}/${retry}` : label)) % L;
    if (s !== 0n) return s;
  }
}

export function deriveKeys(seed, network, account) {
  const ask = scalar(seed, network, account, "ask");
  const nsk = scalar(seed, network, account, "nsk");
  const ak = mul(BASE8, ask);
  const nk = mul(BASE8, nsk);
  const akFold = fold(ak, TAG.ak);
  const nkFold = fold(nk, TAG.nk);
  return {
    network,
    account,
    ask,
    nsk,
    ovk: okm(seed, network, account, "ovk").subarray(0, 32),
    dk: okm(seed, network, account, "dk").subarray(0, 32),
    ak,
    nk,
    akFold,
    nkFold,
    ivk: hash([akFold, nkFold], TAG.ivk) % L,
  };
}

// Returns gd and the cofactor witness q with gd = 8 * q, or null for an invalid diversifier.
export function diversifyHash(d) {
  const dInt = fromLE(d);
  for (let ctr = 0n; ctr <= 255n; ctr++) {
    const u = hash([dInt, ctr], TAG.diversify);
    const u2 = F.square(u);
    const den = F.sub(1n, F.mul(D, u2));
    if (den === 0n) continue;
    const root = F.sqrt(F.div(F.sub(1n, F.mul(A, u2)), den));
    if (root === null) continue;
    const q = [u, root % 2n === 0n ? root : F.neg(root)];
    const gd = timesCofactor(q);
    if (isIdentity(gd)) continue;
    return { gd, q };
  }
  return null;
}

export function diversifier(dk, index) {
  const i = Buffer.alloc(4);
  i.writeUInt32LE(index);
  const mac = createHmac("sha256", dk).update(Buffer.from("cyphras/v2/d")).update(i).digest();
  return mac.subarray(0, 11);
}

function encodeAddress(network, d, pkd) {
  const payload = Uint8Array.from([VERSION, ...d, ...packPoint(pkd)]);
  return bech32m.encode(HRP[network].address, bech32m.toWords(payload));
}

// The address at diversifier index i, or null when d_i is invalid.
export function addressAt(keys, index) {
  const d = diversifier(keys.dk, index);
  const point = diversifyHash(d);
  if (point === null) return null;
  const pkd = mul(point.gd, keys.ivk);
  return { index, d, ...point, pkd, address: encodeAddress(keys.network, d, pkd) };
}

export function defaultAddress(keys) {
  for (let index = 0; ; index++) {
    const address = addressAt(keys, index);
    if (address !== null) return address;
  }
}

export function incomingViewingKey(keys) {
  const payload = Uint8Array.from([VERSION, ...keys.dk, ...toLE32(keys.ivk)]);
  return bech32m.encode(HRP[keys.network].ivk, bech32m.toWords(payload), false);
}

export function fullViewingKey(keys) {
  const payload = Uint8Array.from([
    VERSION,
    ...packPoint(keys.ak),
    ...packPoint(keys.nk),
    ...keys.ovk,
    ...keys.dk,
  ]);
  return bech32m.encode(HRP[keys.network].fvk, bech32m.toWords(payload), false);
}
