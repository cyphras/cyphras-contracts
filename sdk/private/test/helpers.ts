import { readFileSync } from "node:fs";
import { join } from "node:path";
import { sha256 } from "@noble/hashes/sha2";
import { bytesToBigIntBE, concatBytes, le32, utf8 } from "../src/bytes.ts";
import type { TxProofJson } from "../src/extdata.ts";

export const SDK_ROOT = join(import.meta.dirname, "..");
export const REPO_ROOT = join(SDK_ROOT, "..", "..");
export const CIRCUIT_VECTORS = join(REPO_ROOT, "circuits", "test", "vectors");

export function readJson<T>(path: string): T {
  return JSON.parse(readFileSync(path, "utf8")) as T;
}

export function circuitVectors<T>(name: string): T {
  return readJson<T>(join(CIRCUIT_VECTORS, name));
}

export function sdkVectors<T>(name: string): T {
  return readJson<T>(join(SDK_ROOT, "test", "vectors", name));
}

export function fixture<T>(name: string): T {
  return readJson<T>(join(SDK_ROOT, "test", "fixtures", name));
}

// The fixture writes field elements with a 0x prefix; the relayer takes them without one.
const unprefixed = (hex: string): string => hex.replace(/^0x/, "");
export function wireProof(json: TxProofJson): TxProofJson {
  return {
    ...json,
    root: unprefixed(json.root),
    public_amount: unprefixed(json.public_amount),
    ext_data_hash: unprefixed(json.ext_data_hash),
    input_nullifiers: [unprefixed(json.input_nullifiers[0]), unprefixed(json.input_nullifiers[1])],
    output_commitments: [
      unprefixed(json.output_commitments[0]),
      unprefixed(json.output_commitments[1]),
    ],
  };
}

export const MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

// Deterministic bytes, so a failing property test can be replayed.
export function testBytes(label: string, index: number, length: number): Uint8Array {
  const out = new Uint8Array(length);
  for (let block = 0; block * 32 < length; block++) {
    const digest = sha256(concatBytes(utf8(label), le32(index), le32(block)));
    out.set(digest.subarray(0, Math.min(32, length - block * 32)), block * 32);
  }
  return out;
}

export function testScalar(label: string, index: number, modulus: bigint): bigint {
  return bytesToBigIntBE(testBytes(label, index, 64)) % modulus;
}
