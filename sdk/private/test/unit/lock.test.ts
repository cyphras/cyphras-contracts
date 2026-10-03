import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { CyphrasError } from "../../src/errors.ts";
import { MemoryStore, SealedStore } from "../../src/storage.ts";
import { StateStore, emptyState } from "../../src/wallet/state.ts";
import { testBytes } from "../helpers.ts";

const isCode = (code: string) => (err: unknown) => err instanceof CyphrasError && err.code === code;

describe("state compare-and-swap", () => {
  const sealed = (label: number) =>
    new SealedStore(new MemoryStore(), testBytes("lock/store", label, 32));

  it("refuses to save over a state another instance saved since", async () => {
    const store = sealed(0);
    const first = new StateStore(store);
    const state = emptyState(10);
    await first.save(state);
    const second = new StateStore(store);
    const other = (await second.load()) ?? assert.fail("no state");
    await second.save(other);
    await assert.rejects(first.save(state), isCode("state_conflict"));
    const reloaded = (await first.load()) ?? assert.fail("no state");
    assert.equal(reloaded.revision, 2);
    await first.save(reloaded);
    assert.equal(reloaded.revision, 3);
  });

  it("refuses a stored state older than one this instance saw", async () => {
    const backend = new MemoryStore();
    const store = new SealedStore(backend, testBytes("lock/store", 1, 32));
    const states = new StateStore(store);
    const state = emptyState(10);
    await states.save(state);
    const [key] = backend.keys();
    const old = (await backend.get(key as string)) as Uint8Array;
    await states.save(state);
    await backend.set(key as string, old);
    await assert.rejects(states.load(), isCode("state_conflict"));
  });

  it("refuses a state older than the last revision saved, after a reopen too", async () => {
    const backend = new MemoryStore();
    const store = new SealedStore(backend, testBytes("lock/store", 2, 32));
    const states = new StateStore(store);
    const state = emptyState(10);
    await states.save(state);
    // The state record is written first, the record of its revision after it.
    const [key] = backend.keys();
    const old = (await backend.get(key as string)) as Uint8Array;
    await states.save(state);
    await backend.set(key as string, old);
    await assert.rejects(new StateStore(store).load(), isCode("state_conflict"));
    // Nor may the state vanish while its revision stays.
    await backend.delete(key as string);
    await assert.rejects(new StateStore(store).load(), isCode("state_conflict"));
    // A state that could not be read and is discarded starts afresh.
    const fresh = new StateStore(store);
    await fresh.discard();
    assert.equal(await fresh.load(), undefined);
  });
});
