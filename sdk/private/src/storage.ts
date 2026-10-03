import { xchacha20poly1305 } from "@noble/ciphers/chacha";
import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex, concatBytes, randomBytes, utf8 } from "./bytes.ts";
import { fail } from "./errors.ts";

/**
 * The key-value store the SDK keeps its local state in. The SDK encrypts every value it writes,
 * so a backend such as chrome.storage or IndexedDB only ever holds ciphertext. Keys are opaque
 * ASCII strings.
 */
export interface KeyValueStore {
  get(key: string): Promise<Uint8Array | undefined>;
  set(key: string, value: Uint8Array): Promise<void>;
  delete(key: string): Promise<void>;
}

/** A KeyValueStore that lives in memory, for tests and short-lived sessions. */
export class MemoryStore implements KeyValueStore {
  readonly #entries = new Map<string, Uint8Array>();

  async get(key: string): Promise<Uint8Array | undefined> {
    const value = this.#entries.get(key);
    return value === undefined ? undefined : Uint8Array.from(value);
  }

  async set(key: string, value: Uint8Array): Promise<void> {
    this.#entries.set(key, Uint8Array.from(value));
  }

  async delete(key: string): Promise<void> {
    this.#entries.delete(key);
  }

  keys(): string[] {
    return [...this.#entries.keys()];
  }
}

const RECORD_VERSION = 0x01;
const NONCE_LENGTH = 24;

export function sealRecord(key: Uint8Array, aad: Uint8Array, plaintext: Uint8Array): Uint8Array {
  const nonce = randomBytes(NONCE_LENGTH);
  const body = xchacha20poly1305(key, nonce, aad).encrypt(plaintext);
  return concatBytes(Uint8Array.of(RECORD_VERSION), nonce, body);
}

export function openRecord(
  key: Uint8Array,
  aad: Uint8Array,
  record: Uint8Array,
): Uint8Array | undefined {
  if (record.length < 1 + NONCE_LENGTH + 16 || record[0] !== RECORD_VERSION) return undefined;
  try {
    const nonce = record.subarray(1, 1 + NONCE_LENGTH);
    return xchacha20poly1305(key, nonce, aad).decrypt(record.subarray(1 + NONCE_LENGTH));
  } catch {
    return undefined;
  }
}

// Records encrypted with XChaCha20-Poly1305 under the store key sk, with random nonces. Each record
// is bound to its name as associated data, and stored under a name hashed with a key derived from
// sk, so the backend sees neither the contents nor which record is which.
export class SealedStore {
  readonly #backend: KeyValueStore;
  readonly #key: Uint8Array;
  readonly #nameKey: Uint8Array;

  constructor(backend: KeyValueStore, storeKey: Uint8Array) {
    if (storeKey.length !== 32) throw new RangeError("the store key is 32 bytes");
    this.#backend = backend;
    this.#key = Uint8Array.from(storeKey);
    this.#nameKey = hmac(sha256, storeKey, utf8("cyphras/v2/store/names"));
  }

  #location(name: string): string {
    return "cyphras/v2/" + bytesToHex(hmac(sha256, this.#nameKey, utf8(name)).subarray(0, 20));
  }

  async read(name: string): Promise<Uint8Array | undefined> {
    const record = await this.#backend.get(this.#location(name));
    if (record === undefined) return undefined;
    const plaintext = openRecord(this.#key, utf8(`cyphras/v2/store/${name}`), record);
    if (plaintext === undefined) fail("storage_unreadable", "a stored record does not decrypt");
    return plaintext;
  }

  async write(name: string, plaintext: Uint8Array): Promise<void> {
    const record = sealRecord(this.#key, utf8(`cyphras/v2/store/${name}`), plaintext);
    await this.#backend.set(this.#location(name), record);
  }

  async remove(name: string): Promise<void> {
    await this.#backend.delete(this.#location(name));
  }
}
