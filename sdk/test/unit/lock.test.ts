import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { CyphrasError } from "../../src/errors.ts";
import { LEASE_MS, LeaseLock } from "../../src/lock.ts";
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
});

describe("lease lock", () => {
  function clock() {
    let now = 1_000_000;
    return {
      now: () => now,
      sleep: async (ms: number) => {
        now += ms;
        await new Promise((resolve) => setImmediate(resolve));
      },
    };
  }

  const tick = () => new Promise((resolve) => setImmediate(resolve));

  it("lets one holder in at a time", async () => {
    const store = new SealedStore(new MemoryStore(), testBytes("lock/lease", 0, 32));
    const { now, sleep } = clock();
    const a = new LeaseLock(store, now, sleep);
    const b = new LeaseLock(store, now, sleep);
    const order: string[] = [];
    let release = (): void => undefined;
    const gate = new Promise<void>((resolve) => (release = resolve));
    const first = a.hold(async () => {
      order.push("a in");
      await gate;
      order.push("a out");
    });
    await tick();
    const second = b.hold(async () => {
      order.push("b in");
    });
    for (let i = 0; i < 5; i++) await tick();
    assert.deepEqual(order, ["a in"]);
    release();
    await Promise.all([first, second]);
    assert.deepEqual(order, ["a in", "a out", "b in"]);
  });

  it("takes over a lease its holder left to expire, and gives up on one held too long", async () => {
    const store = new SealedStore(new MemoryStore(), testBytes("lock/lease", 1, 32));
    const { now, sleep } = clock();
    const write = (expiresAt: number) =>
      store.write("lease", new TextEncoder().encode(JSON.stringify({ owner: "gone", expiresAt })));
    await write(now() + LEASE_MS / 2);
    const lock = new LeaseLock(store, now, sleep);
    assert.equal(await lock.hold(async () => "held"), "held");
    await write(now() + 10 * LEASE_MS);
    await assert.rejects(
      lock.hold(async () => "never"),
      isCode("account_busy"),
    );
  });
});
