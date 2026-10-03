import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex, randomBytes, utf8 } from "./bytes.ts";
import { fail } from "./errors.ts";
import type { SealedStore } from "./storage.ts";

/** Lets one operation of an account run at a time across the wallet instances sharing its store. */
export interface AccountLock {
  hold<T>(task: () => Promise<T>): Promise<T>;
}

interface LockManager {
  request<T>(name: string, options: { mode: "exclusive" }, task: () => Promise<T>): Promise<T>;
}

// The lock's name comes from the store key, so it says nothing about the account.
export function lockName(storeKey: Uint8Array): string {
  return (
    "cyphras/v2/lock/" + bytesToHex(hmac(sha256, storeKey, utf8("cyphras/v2/lock")).subarray(0, 16))
  );
}

// The Web Locks API, which an extension's pages and service worker share within its origin.
export function webLock(name: string): AccountLock | undefined {
  const locks = (globalThis as { navigator?: { locks?: LockManager } }).navigator?.locks;
  if (typeof locks?.request !== "function") return undefined;
  return { hold: (task) => locks.request(name, { mode: "exclusive" }, task) };
}

const LEASE_RECORD = "lease";
// Longer than any one operation is expected to take; an expired lease is taken over, so a holder
// that died does not lock the account for good.
export const LEASE_MS = 120_000;
const POLL_MS = 250;

interface Lease {
  readonly owner: string;
  readonly expiresAt: number;
}

// A lease kept in the shared store, where the Web Locks API is missing. Writes are not atomic, so
// a lease is confirmed by reading it back, and the state store's compare-and-swap catches the race
// that is left.
export class LeaseLock implements AccountLock {
  readonly #store: SealedStore;
  readonly #now: () => number;
  readonly #sleep: (ms: number) => Promise<void>;
  readonly #owner = bytesToHex(randomBytes(16));

  constructor(store: SealedStore, now: () => number, sleep: (ms: number) => Promise<void>) {
    this.#store = store;
    this.#now = now;
    this.#sleep = sleep;
  }

  async #read(): Promise<Lease | undefined> {
    const bytes = await this.#store.read(LEASE_RECORD);
    return bytes === undefined ? undefined : (JSON.parse(new TextDecoder().decode(bytes)) as Lease);
  }

  async #acquire(): Promise<void> {
    const giveUpAt = this.#now() + 2 * LEASE_MS;
    for (;;) {
      const lease = await this.#read();
      if (lease === undefined || lease.expiresAt <= this.#now() || lease.owner === this.#owner) {
        const mine: Lease = { owner: this.#owner, expiresAt: this.#now() + LEASE_MS };
        await this.#store.write(LEASE_RECORD, utf8(JSON.stringify(mine)));
        if ((await this.#read())?.owner === this.#owner) return;
      }
      if (this.#now() >= giveUpAt) {
        fail("account_busy", "another instance of this wallet holds the account");
      }
      await this.#sleep(POLL_MS);
    }
  }

  async hold<T>(task: () => Promise<T>): Promise<T> {
    await this.#acquire();
    try {
      return await task();
    } finally {
      if ((await this.#read())?.owner === this.#owner) await this.#store.remove(LEASE_RECORD);
    }
  }
}
