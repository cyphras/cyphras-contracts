import { expand, extract } from "@noble/hashes/hkdf";
import { hmac } from "@noble/hashes/hmac";
import { sha256, sha512 } from "@noble/hashes/sha2";
import { A, BASE8, D, L, type Point, isIdentity, scalarMul, timesCofactor } from "./babyjub.ts";
import { bytesToBigIntBE, bytesToBigIntLE, concatBytes, le32, utf8 } from "./bytes.ts";
import { fail } from "./errors.ts";
import { div, mul, neg, sqrt, square, sub } from "./field.ts";
import { hash } from "./poseidon2.ts";

export type Network = "mainnet" | "testnet";

export const NETWORK_PASSPHRASES: Readonly<Record<Network, string>> = {
  mainnet: "Public Global Stellar Network ; September 2015",
  testnet: "Test SDF Network ; September 2015",
};

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
} as const;

// Scalars below L whose fixed-base product the circuit's BabyPbk cannot prove: its last window
// adder would add opposite points. Derivation skips them as it skips zero.
export const UNPROVABLE_SCALARS: readonly bigint[] = [
  0x01c3653c1301a1bc1277bf923de70679621a5b6f148ea4e5d5297349effc94a8n,
  0x03c3653c1301a1bc1277bf923de70679621a5b6f148ea4e5d5297349effc94a8n,
  0x05c3653c1301a1bc1277bf923de70679621a5b6f148ea4e5d5297349effc94a8n,
];

export const SEED_LENGTH = 64;
export const DIVERSIFIER_LENGTH = 11;
const MAX_ACCOUNT = 0x7fffffff;

export function isNetwork(value: unknown): value is Network {
  return value === "mainnet" || value === "testnet";
}

export function checkAccount(account: number): void {
  if (!Number.isInteger(account) || account < 0 || account > MAX_ACCOUNT) {
    fail("invalid_argument", "account must be an integer from 0 to 2^31 - 1");
  }
}

export const fold = (p: Point, tag: number): bigint => hash([p[0], p[1]], tag);

/** Keys that detect and read incoming notes. */
export interface IncomingKeys {
  readonly network: Network;
  readonly dk: Uint8Array;
  readonly ivk: bigint;
}

/** Keys that also detect spends and recover outgoing notes. */
export interface FullViewingKeys extends IncomingKeys {
  readonly ak: Point;
  readonly nk: Point;
  readonly akFold: bigint;
  readonly nkFold: bigint;
  readonly ovk: Uint8Array;
}

/** Keys that also authorize spends. */
export interface SpendingKeys extends FullViewingKeys {
  readonly account: number;
  readonly ask: bigint;
  readonly nsk: bigint;
  readonly storeKey: Uint8Array;
}

const PRK_SALT = utf8("cyphras/v2/shielded");

export function usableScalar(s: bigint): boolean {
  return s !== 0n && !UNPROVABLE_SCALARS.includes(s);
}

export function deriveIvk(akFold: bigint, nkFold: bigint): bigint {
  return hash([akFold, nkFold], TAG.ivk) % L;
}

export function viewingKeysFromPoints(
  network: Network,
  ak: Point,
  nk: Point,
  ovk: Uint8Array,
  dk: Uint8Array,
): FullViewingKeys {
  const akFold = fold(ak, TAG.ak);
  const nkFold = fold(nk, TAG.nk);
  return { network, ak, nk, akFold, nkFold, ivk: deriveIvk(akFold, nkFold), ovk, dk };
}

export function deriveSpendingKeys(
  seed: Uint8Array,
  network: Network,
  account: number,
): SpendingKeys {
  if (seed.length !== SEED_LENGTH) fail("invalid_argument", "the seed must be 64 bytes");
  if (!isNetwork(network)) fail("invalid_argument", "unknown network");
  checkAccount(account);
  const prk = extract(sha512, seed, PRK_SALT);
  const okm = (label: string): Uint8Array =>
    expand(sha512, prk, utf8(`${network}/${account}/${label}`), 64);
  const scalar = (label: string): bigint => {
    for (let retry = 0; ; retry++) {
      const s = bytesToBigIntBE(okm(retry === 0 ? label : `${label}/${retry}`)) % L;
      if (usableScalar(s)) return s;
    }
  };
  const ask = scalar("ask");
  const nsk = scalar("nsk");
  const viewing = viewingKeysFromPoints(
    network,
    scalarMul(BASE8, ask),
    scalarMul(BASE8, nsk),
    okm("ovk").slice(0, 32),
    okm("dk").slice(0, 32),
  );
  // ivk = 0 would put every address at the identity; it occurs with probability about 2^-251.
  if (viewing.ivk === 0n) fail("invalid_argument", "this seed yields an unusable key");
  return { ...viewing, account, ask, nsk, storeKey: okm("store").slice(0, 32) };
}

export interface Diversified {
  readonly gd: Point;
  // The cofactor witness q with gd = 8 * q, which a spend of a note at this address needs.
  readonly q: Point;
}

export function diversifyHash(d: Uint8Array): Diversified | undefined {
  if (d.length !== DIVERSIFIER_LENGTH) return undefined;
  const dInt = bytesToBigIntLE(d);
  for (let ctr = 0n; ctr <= 255n; ctr++) {
    const u = hash([dInt, ctr], TAG.diversify);
    const u2 = square(u);
    const den = sub(1n, mul(D, u2));
    if (den === 0n) continue;
    const root = sqrt(div(sub(1n, mul(A, u2)), den));
    if (root === undefined) continue;
    const q: Point = [u, root % 2n === 0n ? root : neg(root)];
    const gd = timesCofactor(q);
    if (isIdentity(gd)) continue;
    return { gd, q };
  }
  return undefined;
}

export function diversifier(dk: Uint8Array, index: number): Uint8Array {
  const mac = hmac(sha256, dk, concatBytes(utf8("cyphras/v2/d"), le32(index)));
  return mac.slice(0, DIVERSIFIER_LENGTH);
}

export interface AddressKey extends Diversified {
  readonly d: Uint8Array;
  readonly pkd: Point;
}

export function addressKeyFor(keys: IncomingKeys, d: Uint8Array): AddressKey | undefined {
  const diversified = diversifyHash(d);
  if (diversified === undefined) return undefined;
  return { d, ...diversified, pkd: scalarMul(diversified.gd, keys.ivk) };
}

export function addressKeyAt(keys: IncomingKeys, index: number): AddressKey | undefined {
  return addressKeyFor(keys, diversifier(keys.dk, index));
}

export function defaultAddressKey(keys: IncomingKeys): AddressKey & { readonly index: number } {
  for (let index = 0; ; index++) {
    const key = addressKeyAt(keys, index);
    if (key !== undefined) return { ...key, index };
  }
}
