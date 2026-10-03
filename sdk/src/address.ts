import { bech32m } from "@scure/base";
import { L, type Point, inPrimeSubgroup, isIdentity, packPoint, unpackPoint } from "./babyjub.ts";
import { bigIntToBytesLE, bytesToBigIntLE, concatBytes } from "./bytes.ts";
import { CyphrasError, type ErrorCode } from "./errors.ts";
import {
  type AddressKey,
  DIVERSIFIER_LENGTH,
  type FullViewingKeys,
  type IncomingKeys,
  type Network,
  diversifyHash,
  viewingKeysFromPoints,
} from "./keys.ts";

export const VERSION = 0x02;
const ADDRESS_LENGTH = 1 + DIVERSIFIER_LENGTH + 32;
const IVK_LENGTH = 65;
const FVK_LENGTH = 129;
const ADDRESS_LIMIT = 90;

export const HRP: Readonly<Record<Network, { address: string; ivk: string; fvk: string }>> = {
  mainnet: { address: "cy", ivk: "cyivk", fvk: "cyfvk" },
  testnet: { address: "cyt", ivk: "cytivk", fvk: "cytfvk" },
};

/** The rule an address or viewing key breaks, as named in the reject vectors. */
export type EncodingRule =
  | "bech32m"
  | "hrp"
  | "version"
  | "length"
  | "diversifier"
  | "point"
  | "identity"
  | "subgroup"
  | "ivk_range";

// The input is never echoed: a viewing key is a secret, and the bech32 library's own errors
// quote the string they reject.
function reject(code: ErrorCode, what: string, rule: EncodingRule): never {
  throw new CyphrasError(code, `${what} is invalid: ${rule}`, { rule });
}

function decodePayload(
  code: ErrorCode,
  what: string,
  text: unknown,
  prefixes: readonly string[],
  limit: number | false,
): { prefix: string; payload: Uint8Array } {
  if (typeof text !== "string") reject(code, what, "bech32m");
  let decoded: { prefix: string; words: number[] };
  try {
    decoded = bech32m.decode(text as `${string}1${string}`, limit);
  } catch {
    reject(code, what, "bech32m");
  }
  if (!prefixes.includes(decoded.prefix)) reject(code, what, "hrp");
  const payload = bech32m.fromWordsUnsafe(decoded.words);
  if (payload === undefined) reject(code, what, "bech32m");
  if (payload[0] !== VERSION) reject(code, what, "version");
  return { prefix: decoded.prefix, payload: Uint8Array.from(payload) };
}

function primeOrderPoint(code: ErrorCode, what: string, bytes: Uint8Array): Point {
  const p = unpackPoint(bytes);
  if (p === undefined) reject(code, what, "point");
  if (isIdentity(p)) reject(code, what, "identity");
  if (!inPrimeSubgroup(p)) reject(code, what, "subgroup");
  return p;
}

export function encodeAddress(network: Network, d: Uint8Array, pkd: Point): string {
  const payload = concatBytes(Uint8Array.of(VERSION), d, packPoint(pkd));
  return bech32m.encode(HRP[network].address, bech32m.toWords(payload), ADDRESS_LIMIT);
}

export function decodeAddress(network: Network, text: unknown): AddressKey {
  const what = "address";
  const { payload } = decodePayload(
    "invalid_address",
    what,
    text,
    [HRP[network].address],
    ADDRESS_LIMIT,
  );
  if (payload.length !== ADDRESS_LENGTH) reject("invalid_address", what, "length");
  const d = payload.slice(1, 1 + DIVERSIFIER_LENGTH);
  const diversified = diversifyHash(d);
  if (diversified === undefined) reject("invalid_address", what, "diversifier");
  const pkd = primeOrderPoint("invalid_address", what, payload.subarray(1 + DIVERSIFIER_LENGTH));
  return { d, ...diversified, pkd };
}

export function encodeIncomingViewingKey(keys: IncomingKeys): string {
  const payload = concatBytes(Uint8Array.of(VERSION), keys.dk, bigIntToBytesLE(keys.ivk, 32));
  return bech32m.encode(HRP[keys.network].ivk, bech32m.toWords(payload), false);
}

export function encodeFullViewingKey(keys: FullViewingKeys): string {
  const payload = concatBytes(
    Uint8Array.of(VERSION),
    packPoint(keys.ak),
    packPoint(keys.nk),
    keys.ovk,
    keys.dk,
  );
  return bech32m.encode(HRP[keys.network].fvk, bech32m.toWords(payload), false);
}

export type ViewingKey =
  | { readonly kind: "incoming"; readonly keys: IncomingKeys }
  | { readonly kind: "full"; readonly keys: FullViewingKeys };

export function decodeViewingKey(network: Network, text: unknown): ViewingKey {
  const code = "invalid_viewing_key";
  const what = "viewing key";
  const hrp = HRP[network];
  const { prefix, payload } = decodePayload(code, what, text, [hrp.ivk, hrp.fvk], false);
  if (prefix === hrp.ivk) {
    if (payload.length !== IVK_LENGTH) reject(code, what, "length");
    const ivk = bytesToBigIntLE(payload.subarray(33));
    if (ivk >= L) reject(code, what, "ivk_range");
    return { kind: "incoming", keys: { network, dk: payload.slice(1, 33), ivk } };
  }
  if (payload.length !== FVK_LENGTH) reject(code, what, "length");
  const ak = primeOrderPoint(code, what, payload.subarray(1, 33));
  const nk = primeOrderPoint(code, what, payload.subarray(33, 65));
  const keys = viewingKeysFromPoints(network, ak, nk, payload.slice(65, 97), payload.slice(97));
  return { kind: "full", keys };
}
