import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { mnemonicToSeedSync } from "@scure/bip39";
import {
  type EncodingRule,
  HRP,
  decodeAddress,
  decodeViewingKey,
  encodeAddress,
  encodeFullViewingKey,
  encodeIncomingViewingKey,
} from "../../src/address.ts";
import { type Point, packPoint } from "../../src/babyjub.ts";
import { bytesToHex, toHex32 } from "../../src/bytes.ts";
import { CyphrasError } from "../../src/errors.ts";
import {
  type Network,
  UNPROVABLE_SCALARS,
  addressKeyAt,
  defaultAddressKey,
  deriveSpendingKeys,
  diversifier,
  usableScalar,
} from "../../src/keys.ts";
import { MNEMONIC, circuitVectors } from "../helpers.ts";

interface HexPoint {
  x: string;
  y: string;
}

interface KeyVectors {
  mnemonic: string;
  passphrase: string;
  seed: string;
  unprovable_scalars: string[];
  accounts: {
    network: Network;
    account: number;
    ask: string;
    nsk: string;
    ovk: string;
    dk: string;
    sk: string;
    ak: HexPoint;
    ak_packed: string;
    nk: HexPoint;
    nk_packed: string;
    ak_fold: string;
    nk_fold: string;
    ivk: string;
    diversifiers: {
      index: number;
      d: string;
      valid: boolean;
      q?: HexPoint;
      g_d?: HexPoint;
      pk_d?: HexPoint;
      pk_d_packed?: string;
      address?: string;
    }[];
    default_address_index: number;
    incoming_viewing_key: string;
    full_viewing_key: string;
  }[];
}

interface InvalidVector {
  network: Network;
  encoding: string;
  rule: EncodingRule;
  reason: string;
}

interface InvalidVectors {
  rules: Record<string, string>;
  address: InvalidVector[];
  incoming_viewing_key: InvalidVector[];
  full_viewing_key: InvalidVector[];
}

const KEYS = circuitVectors<KeyVectors>("keys.json");
const INVALID = circuitVectors<InvalidVectors>("invalid-encodings.json");
const point = (p: Point): HexPoint => ({ x: toHex32(p[0]), y: toHex32(p[1]) });

function rejectsWith(fn: () => unknown, code: string, rule: string, reason: string): void {
  assert.throws(
    fn,
    (err: unknown) =>
      err instanceof CyphrasError && err.code === code && err.details["rule"] === rule,
    reason,
  );
}

describe("keys", () => {
  const seed = mnemonicToSeedSync(KEYS.mnemonic, KEYS.passphrase);

  it("starts from the BIP39 seed of the test mnemonic", () => {
    assert.equal(KEYS.mnemonic, MNEMONIC);
    assert.equal(bytesToHex(seed), KEYS.seed);
  });

  it("skips zero and the three scalars the circuit cannot prove", () => {
    assert.deepEqual(UNPROVABLE_SCALARS.map(toHex32), KEYS.unprovable_scalars);
    for (const s of [0n, ...UNPROVABLE_SCALARS]) assert.equal(usableScalar(s), false);
    assert.equal(usableScalar(1n), true);
  });

  for (const v of KEYS.accounts) {
    describe(`${v.network} account ${v.account}`, () => {
      const keys = deriveSpendingKeys(seed, v.network, v.account);

      it("derives every key in keys.json", () => {
        assert.equal(toHex32(keys.ask), v.ask);
        assert.equal(toHex32(keys.nsk), v.nsk);
        assert.equal(bytesToHex(keys.ovk), v.ovk);
        assert.equal(bytesToHex(keys.dk), v.dk);
        assert.equal(bytesToHex(keys.storeKey), v.sk);
        assert.deepEqual(point(keys.ak), v.ak);
        assert.equal(bytesToHex(packPoint(keys.ak)), v.ak_packed);
        assert.deepEqual(point(keys.nk), v.nk);
        assert.equal(bytesToHex(packPoint(keys.nk)), v.nk_packed);
        assert.equal(toHex32(keys.akFold), v.ak_fold);
        assert.equal(toHex32(keys.nkFold), v.nk_fold);
        assert.equal(toHex32(keys.ivk), v.ivk);
      });

      it("derives every diversified address in keys.json", () => {
        for (const dv of v.diversifiers) {
          assert.equal(bytesToHex(diversifier(keys.dk, dv.index)), dv.d);
          const a = addressKeyAt(keys, dv.index);
          assert.equal(a !== undefined, dv.valid);
          if (a === undefined) continue;
          assert.deepEqual(point(a.q), dv.q);
          assert.deepEqual(point(a.gd), dv.g_d);
          assert.deepEqual(point(a.pkd), dv.pk_d);
          assert.equal(bytesToHex(packPoint(a.pkd)), dv.pk_d_packed);
          const encoded = encodeAddress(v.network, a.d, a.pkd);
          assert.equal(encoded, dv.address);
          assert.equal(encoded.length, v.network === "mainnet" ? 80 : 81);
          for (const text of [encoded, encoded.toUpperCase()]) {
            const decoded = decodeAddress(v.network, text);
            assert.deepEqual([bytesToHex(decoded.d), decoded.gd, decoded.pkd], [dv.d, a.gd, a.pkd]);
            assert.deepEqual(decoded.q, a.q);
          }
        }
        assert.equal(defaultAddressKey(keys).index, v.default_address_index);
      });

      it("encodes and decodes both viewing keys", () => {
        assert.equal(encodeIncomingViewingKey(keys), v.incoming_viewing_key);
        assert.equal(encodeFullViewingKey(keys), v.full_viewing_key);
        const incoming = decodeViewingKey(v.network, v.incoming_viewing_key);
        assert.equal(incoming.kind, "incoming");
        assert.equal(incoming.keys.ivk, keys.ivk);
        assert.equal(bytesToHex(incoming.keys.dk), v.dk);
        const full = decodeViewingKey(v.network, v.full_viewing_key);
        assert.ok(full.kind === "full");
        assert.deepEqual([full.keys.ak, full.keys.nk], [keys.ak, keys.nk]);
        assert.equal(full.keys.ivk, keys.ivk);
        assert.equal(full.keys.nkFold, keys.nkFold);
        assert.deepEqual([bytesToHex(full.keys.ovk), bytesToHex(full.keys.dk)], [v.ovk, v.dk]);
      });
    });
  }

  it("gives unrelated keys per network and account", () => {
    const all = KEYS.accounts.map((v) => deriveSpendingKeys(seed, v.network, v.account));
    for (const field of ["ask", "nsk", "ivk"] as const) {
      assert.equal(new Set(all.map((k) => k[field])).size, all.length);
    }
  });

  it("refuses a seed of the wrong length and a bad account", () => {
    assert.throws(() => deriveSpendingKeys(seed.subarray(0, 32), "mainnet", 0));
    assert.throws(() => deriveSpendingKeys(seed, "mainnet", -1));
    assert.throws(() => deriveSpendingKeys(seed, "mainnet", 1.5));
    assert.throws(() => deriveSpendingKeys(seed, "mainnet", 2 ** 31));
  });
});

describe("invalid encodings", () => {
  it("covers every rule of the vector file", () => {
    const rules: EncodingRule[] = [
      "hrp",
      "version",
      "length",
      "bech32m",
      "point",
      "identity",
      "subgroup",
      "ivk_range",
    ];
    assert.deepEqual(Object.keys(INVALID.rules).sort(), [...rules].sort());
  });

  for (const v of INVALID.address) {
    it(`rejects an address: ${v.reason} (${v.rule})`, () => {
      rejectsWith(() => decodeAddress(v.network, v.encoding), "invalid_address", v.rule, v.reason);
    });
  }

  for (const kind of ["incoming_viewing_key", "full_viewing_key"] as const) {
    for (const v of INVALID[kind]) {
      it(`rejects a ${kind.replaceAll("_", " ")}: ${v.reason} (${v.rule})`, () => {
        rejectsWith(
          () => decodeViewingKey(v.network, v.encoding),
          "invalid_viewing_key",
          v.rule,
          v.reason,
        );
      });
    }
  }

  it("never quotes a rejected viewing key in the error", () => {
    const key = KEYS.accounts[0]?.full_viewing_key as string;
    const broken = key.slice(0, -1) + (key.endsWith("q") ? "p" : "q");
    try {
      decodeViewingKey("mainnet", broken);
      assert.fail("decoded a corrupted key");
    } catch (err) {
      assert.ok(err instanceof CyphrasError);
      assert.ok(!err.message.includes(broken.slice(10, 40)));
      assert.ok(!JSON.stringify(err.details).includes(broken.slice(10, 40)));
    }
  });

  it("rejects a viewing key of the other network and an address as a key", () => {
    const testnetKey = KEYS.accounts.find((a) => a.network === "testnet");
    rejectsWith(
      () => decodeViewingKey("mainnet", testnetKey?.incoming_viewing_key),
      "invalid_viewing_key",
      "hrp",
      "testnet key",
    );
    const address = KEYS.accounts[0]?.diversifiers[0]?.address;
    rejectsWith(() => decodeViewingKey("mainnet", address), "invalid_viewing_key", "hrp", "addr");
    assert.equal(HRP.testnet.address, "cyt");
  });

  it("rejects non-string input", () => {
    rejectsWith(() => decodeAddress("mainnet", 42), "invalid_address", "bech32m", "number");
    rejectsWith(() => decodeViewingKey("mainnet", null), "invalid_viewing_key", "bech32m", "null");
  });
});
