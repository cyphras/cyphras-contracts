import { randomBytes as nobleRandomBytes } from "@noble/hashes/utils";

const HEX = /^(?:[0-9a-f]{2})*$/;

export function hexToBytes(hex: string): Uint8Array {
  if (!HEX.test(hex)) throw new TypeError("expected lowercase hex of even length");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return out;
}

export function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

// Constant time in the length of the inputs, so comparing tags and keys leaks no prefix length.
export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] as number) ^ (b[i] as number);
  return diff === 0;
}

export function utf8(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

export function bytesToBigIntBE(bytes: Uint8Array): bigint {
  return bytes.length === 0 ? 0n : BigInt("0x" + bytesToHex(bytes));
}

export function bytesToBigIntLE(bytes: Uint8Array): bigint {
  return bytesToBigIntBE(Uint8Array.from(bytes).reverse());
}

export function bigIntToBytesBE(value: bigint, length: number): Uint8Array {
  if (value < 0n || value >= 1n << BigInt(8 * length)) {
    throw new RangeError(`value does not fit in ${length} bytes`);
  }
  return hexToBytes(value.toString(16).padStart(2 * length, "0"));
}

export function bigIntToBytesLE(value: bigint, length: number): Uint8Array {
  return bigIntToBytesBE(value, length).reverse();
}

export function le32(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
    throw new RangeError("expected a 32-bit unsigned integer");
  }
  return bigIntToBytesLE(BigInt(value), 4);
}

export function randomBytes(length: number): Uint8Array {
  return nobleRandomBytes(length);
}

// The form the reference vectors and the vault fixtures use for field elements.
export function toHex32(value: bigint): string {
  return "0x" + bytesToHex(bigIntToBytesBE(value, 32));
}
