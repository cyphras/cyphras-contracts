import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex, utf8 } from "./bytes.ts";

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

// For a store only one wallet instance uses, whose own queue already runs one operation at a time.
export const soleInstance: AccountLock = { hold: (task) => task() };
