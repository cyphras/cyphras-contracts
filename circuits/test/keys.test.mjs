import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { bech32m } from "@scure/base";
import {
  L,
  inPrimeSubgroup,
  isIdentity,
  mul,
  onCurve,
  packPoint,
  timesCofactor,
} from "../reference/babyjub.mjs";
import {
  addressAt,
  bip39Seed,
  defaultAddress,
  deriveKeys,
  diversifier,
  diversifyHash,
  fullViewingKey,
  incomingViewingKey,
} from "../reference/keys.mjs";
import { MNEMONIC } from "../reference/vectors.mjs";

// BIP39 reference vector for this mnemonic with an empty passphrase.
const SEED_HEX =
  "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1" +
  "9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";

const seed = bip39Seed(MNEMONIC);
const decode = (s) => {
  const { prefix, words } = bech32m.decode(s, false);
  return { prefix, payload: Buffer.from(bech32m.fromWords(words)) };
};

describe("keys", () => {
  it("derives the BIP39 seed of the test mnemonic", () => {
    assert.equal(seed.toString("hex"), SEED_HEX);
  });

  // With L = 64, HKDF-Expand is a single HMAC block, so the info string can be checked directly.
  it("derives ask from HKDF-SHA512 with the network and account in the info string", () => {
    const prk = createHmac("sha512", "cyphras/v2/shielded").update(seed).digest();
    const okm = createHmac("sha512", prk)
      .update("testnet/1/ask")
      .update(Buffer.from([1]))
      .digest();
    assert.equal(deriveKeys(seed, "testnet", 1).ask, BigInt("0x" + okm.toString("hex")) % L);
  });

  it("gives unrelated keys per network and account", () => {
    const all = ["mainnet", "testnet"].flatMap((n) => [0, 1, 2].map((a) => deriveKeys(seed, n, a)));
    for (const field of ["ask", "nsk", "ivk"]) {
      assert.equal(new Set(all.map((k) => k[field])).size, all.length, field);
    }
    for (const k of all) {
      for (const s of [k.ask, k.nsk, k.ivk]) assert.ok(s > 0n && s < L);
      assert.deepEqual(mul(k.ak, L), [0n, 1n]);
    }
  });

  describe("DiversifyHash", () => {
    const { dk } = deriveKeys(seed, "mainnet", 0);
    const results = Array.from({ length: 16 }, (_, i) => diversifyHash(diversifier(dk, i)));

    it("maps diversifiers to prime-order points with an on-curve cofactor witness", () => {
      for (const r of results) {
        assert.ok(onCurve(r.q));
        assert.equal(r.q[1] % 2n, 0n);
        assert.deepEqual(timesCofactor(r.q), r.gd);
        assert.ok(inPrimeSubgroup(r.gd) && !isIdentity(r.gd));
      }
      assert.equal(new Set(results.map((r) => r.gd[0])).size, results.length);
    });

    it("is deterministic", () => {
      assert.deepEqual(diversifyHash(diversifier(dk, 3)), results[3]);
    });
  });

  describe("encodings", () => {
    for (const [network, hrp, length] of [
      ["mainnet", "cy", 80],
      ["testnet", "cyt", 81],
    ]) {
      it(`encodes ${network} addresses as ${length}-character bech32m`, () => {
        const keys = deriveKeys(seed, network, 0);
        for (const i of [0, 1, 2]) {
          const a = addressAt(keys, i);
          assert.equal(a.address.length, length);
          const { prefix, payload } = decode(a.address);
          assert.equal(prefix, hrp);
          assert.deepEqual(payload, Buffer.from([0x02, ...a.d, ...packPoint(a.pkd)]));
          assert.deepEqual(a.pkd, mul(a.gd, keys.ivk));
        }
        assert.equal(defaultAddress(keys).index, 0);
      });
    }

    it("encodes both viewing keys", () => {
      const keys = deriveKeys(seed, "testnet", 0);
      const ivk = decode(incomingViewingKey(keys));
      assert.equal(ivk.prefix, "cytivk");
      assert.equal(ivk.payload.length, 65);
      assert.deepEqual(ivk.payload.subarray(1, 33), keys.dk);
      assert.equal(
        BigInt("0x" + Buffer.from(ivk.payload.subarray(33)).reverse().toString("hex")),
        keys.ivk,
      );
      const fvk = decode(fullViewingKey(keys));
      assert.equal(fvk.prefix, "cytfvk");
      assert.equal(fvk.payload.length, 129);
      assert.deepEqual(fvk.payload.subarray(1, 33), Buffer.from(packPoint(keys.ak)));
    });
  });
});
