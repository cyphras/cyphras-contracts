import assert from "node:assert/strict";
import { createHash, createPrivateKey, sign as nodeSign } from "node:crypto";
import { describe, it } from "node:test";
import { ed25519 } from "@noble/curves/ed25519";
import { base64, base64nopad, base64url, base64urlnopad } from "@scure/base";
import { mnemonicToSeedSync, validateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english";
import { StrKey } from "@stellar/stellar-base";
import { encodeAddress } from "../../src/address.ts";
import { bytesToHex, hexToBytes, utf8 } from "../../src/bytes.ts";
import { CyphrasError } from "../../src/errors.ts";
import { defaultAddressKey, deriveSpendingKeys } from "../../src/keys.ts";
import {
  type MessageSigner,
  isKeyDerivationMessage,
  keySource,
  sep53Digest,
  signatureMessage,
  signatureSeed,
  verifySep53,
} from "../../src/keysource.ts";
import { MemoryStore, SealedStore } from "../../src/storage.ts";
import { SEP5_ACCOUNT_0, sigSeedVectors, slip10Ed25519 } from "../../scripts/vectors.ts";
import { MNEMONIC, sdkVectors } from "../helpers.ts";

interface NetworkVectors {
  message: string;
  message_length: number;
  message_sha256: string;
  sep53_digest: string;
  signature: string;
  signature_base64: string;
  seed: string;
  default_address: string;
}

interface SigSeedVectors {
  signer: { mnemonic: string; path: string; account: string };
  mainnet: NetworkVectors;
  testnet: NetworkVectors;
}

const NETWORKS = ["mainnet", "testnet"] as const;

const VECTORS = sdkVectors<SigSeedVectors>("sig-seed.json");
const SECRET = slip10Ed25519(mnemonicToSeedSync(MNEMONIC), SEP5_ACCOUNT_0);

// SEP-0005 Test 5 accounts of the same mnemonic.
const SEP5_TEST_5 = [
  "GB3JDWCQJCWMJ3IILWIGDTQJJC5567PGVEVXSCVPEQOTDN64VJBDQBYX",
  "GDVSYYTUAJ3ACHTPQNSTQBDQ4LDHQCMNY4FCEQH5TJUMSSLWQSTG42MV",
  "GBFPWBTN4AXHPWPTQVQBP4KRZ2YVYYOGRMV2PEYL2OBPPJDP7LECEVHR",
];

function signer(
  secret: Uint8Array,
  sign: (digest: Uint8Array, call: number) => unknown = (d) => ed25519.sign(d, secret),
): MessageSigner & { calls: number } {
  const s = {
    publicKey: StrKey.encodeEd25519PublicKey(Buffer.from(ed25519.getPublicKey(secret))),
    calls: 0,
    async signMessage(message: string): Promise<unknown> {
      return sign(sep53Digest(message), s.calls++);
    },
  };
  return s;
}

async function rejects(promise: Promise<unknown>, code: string): Promise<void> {
  await assert.rejects(promise, (err: unknown) => err instanceof CyphrasError && err.code === code);
}

describe("signature seed vectors", () => {
  it("sig-seed.json matches a fresh run", () => {
    assert.deepEqual(VECTORS, JSON.parse(JSON.stringify(sigSeedVectors())));
  });

  it("pins the message the signature key source signs on each network", () => {
    const pinned = {
      mainnet: [211, "0bf58e49e97c20e12f2d6bfc2cdd49e3e6d0052a2522500cd05114107d1eb571"],
      testnet: [211, "ab5374d0c196f433c5e0e747335794236383c6662c20ddc7e0491cc7dd2ef935"],
    } as const;
    for (const network of NETWORKS) {
      const message = signatureMessage(network);
      assert.equal(VECTORS[network].message, message);
      assert.equal(utf8(message).length, pinned[network][0]);
      assert.equal(VECTORS[network].message_sha256, pinned[network][1]);
      assert.ok(/^[\x20-\x7e\n]+$/.test(message) && !message.endsWith("\n"));
      assert.ok(message.split("\n")[1] === `Network: Stellar ${network}`);
    }
  });

  it("gives each network its own signature, seed and account", () => {
    assert.notEqual(VECTORS.mainnet.sep53_digest, VECTORS.testnet.sep53_digest);
    assert.notEqual(VECTORS.mainnet.seed, VECTORS.testnet.seed);
    const testnetSignature = hexToBytes(VECTORS.testnet.signature);
    assert.equal(
      verifySep53(VECTORS.signer.account, signatureMessage("mainnet"), testnetSignature),
      false,
    );
    assert.equal(
      verifySep53(VECTORS.signer.account, signatureMessage("testnet"), testnetSignature),
      true,
    );
  });

  it("derives the SEP-0005 accounts of the test mnemonic", () => {
    const seed = mnemonicToSeedSync(MNEMONIC);
    SEP5_TEST_5.forEach((expected, account) => {
      const secret = slip10Ed25519(seed, [44, 148, account]);
      const key = StrKey.encodeEd25519PublicKey(Buffer.from(ed25519.getPublicKey(secret)));
      assert.equal(key, expected);
    });
    assert.equal(VECTORS.signer.account, SEP5_TEST_5[0]);
  });

  it("signs the SEP-53 digest as OpenSSL's Ed25519 does", () => {
    const publicKey = ed25519.getPublicKey(SECRET);
    const jwk = {
      kty: "OKP",
      crv: "Ed25519",
      d: Buffer.from(SECRET).toString("base64url"),
      x: Buffer.from(publicKey).toString("base64url"),
    };
    for (const network of NETWORKS) {
      const v = VECTORS[network];
      const message = signatureMessage(network);
      const expected = Buffer.concat([
        Buffer.from("Stellar Signed Message:\n"),
        Buffer.from(message),
      ]);
      assert.equal(bytesToHex(sep53Digest(message)), v.sep53_digest);
      assert.equal(v.sep53_digest, createHash("sha256").update(expected).digest("hex"));
      const signature = nodeSign(
        null,
        hexToBytes(v.sep53_digest),
        createPrivateKey({ key: jwk, format: "jwk" }),
      );
      assert.equal(signature.toString("hex"), v.signature);
      assert.equal(Buffer.from(signature).toString("base64"), v.signature_base64);
      assert.ok(verifySep53(VECTORS.signer.account, message, signature));
    }
  });

  it("derives the seed and its default address", () => {
    for (const network of NETWORKS) {
      const seed = signatureSeed(hexToBytes(VECTORS[network].signature));
      assert.equal(bytesToHex(seed), VECTORS[network].seed);
      const key = defaultAddressKey(deriveSpendingKeys(seed, network, 0));
      assert.equal(encodeAddress(network, key.d, key.pkd), VECTORS[network].default_address);
    }
  });
});

// The message SDK 0.1 asked for on both networks, which a wallet still warns about.
const NETWORKLESS = signatureMessage("mainnet").replace("\nNetwork: Stellar mainnet", "");

describe("the key-derivation message", () => {
  it("is recognized in every form a signer could be asked to sign it in", () => {
    for (const message of [signatureMessage("mainnet"), signatureMessage("testnet"), NETWORKLESS]) {
      const prefixed = `Stellar Signed Message:\n${message}`;
      const digest = sep53Digest(message);
      for (const form of [
        message,
        message.replace(/\n/g, "\r\n"),
        message.replace(/\n/g, "\r"),
        `\n  ${message}  \n`,
        message.split("\n").join(" \n"),
        utf8(message),
        bytesToHex(utf8(message)),
        bytesToHex(utf8(message)).toUpperCase(),
        base64.encode(utf8(message)),
        prefixed,
        utf8(prefixed),
        digest,
        bytesToHex(digest),
        `0x${bytesToHex(digest)}`,
        `0X${bytesToHex(digest).toUpperCase()}`,
        `0x${bytesToHex(utf8(message))}`,
        (bytesToHex(digest).match(/../g) as string[]).join(" "),
        base64.encode(digest),
        base64nopad.encode(digest),
        base64url.encode(digest),
        base64urlnopad.encode(digest),
        base64nopad.encode(utf8(message)),
      ]) {
        assert.equal(isKeyDerivationMessage(form), true, String(form).slice(0, 48));
      }
    }
  });

  it("is not taken for another message", () => {
    const message = signatureMessage("mainnet");
    for (const other of [
      "",
      "Sign in to example.com",
      message.replace("v2", "v3"),
      message.replace("mainnet", "futurenet"),
      `Sign in\n\n${message}`,
      message.toUpperCase(),
      new Uint8Array(32),
      utf8(message).subarray(1),
      sep53Digest(`Stellar Signed Message:\n${message}`),
    ]) {
      assert.equal(isKeyDerivationMessage(other), false, String(other).slice(0, 48));
    }
  });
});

describe("key sources", () => {
  const context = { network: "testnet" as const, storage: new MemoryStore() };

  it("(a) gives the BIP39 seed of the mnemonic at the requested account", async () => {
    const material = await keySource.mnemonic(MNEMONIC, { account: 3 }).resolve(context);
    assert.deepEqual(material.seed, Uint8Array.from(mnemonicToSeedSync(MNEMONIC)));
    assert.equal(material.account, 3);
    const spaced = `  ${MNEMONIC.split(" ").join("   ")} `;
    const again = await keySource.mnemonic(spaced, { account: 0 }).resolve(context);
    assert.deepEqual(again.seed, material.seed);
    const words = await keySource.mnemonic(MNEMONIC.split(" "), { account: 0 }).resolve(context);
    assert.deepEqual(words.seed, material.seed);
    const pass = await keySource
      .mnemonic(MNEMONIC, { account: 0, passphrase: "TREZOR" })
      .resolve(context);
    assert.deepEqual(pass.seed, Uint8Array.from(mnemonicToSeedSync(MNEMONIC, "TREZOR")));
  });

  it("(a) refuses an invalid mnemonic or account", () => {
    assert.throws(
      () => keySource.mnemonic(MNEMONIC.replace("about", "abandon"), { account: 0 }),
      (err: unknown) => err instanceof CyphrasError && err.code === "invalid_mnemonic",
    );
    assert.throws(() => keySource.mnemonic(MNEMONIC, { account: -1 }));
  });

  it("(c) creates a 24-word mnemonic that restores under (a)", async () => {
    const source = keySource.random();
    const mnemonic = source.revealMnemonic();
    assert.equal(mnemonic.split(" ").length, 24);
    assert.ok(validateMnemonic(mnemonic, wordlist));
    const material = await source.resolve(context);
    const restored = await keySource.mnemonic(mnemonic, { account: 0 }).resolve(context);
    assert.deepEqual(material, restored);
    assert.notEqual(keySource.random().revealMnemonic(), mnemonic);
  });

  it("(b) asks twice on first use, then once, and yields the vector seed", async () => {
    const storage = new MemoryStore();
    const s = signer(SECRET);
    const first = await keySource.signature(s).resolve({ network: "mainnet", storage });
    assert.equal(bytesToHex(first.seed), VECTORS.mainnet.seed);
    assert.equal(first.account, 0);
    assert.equal(s.calls, 2);
    const later = await keySource.signature(s).resolve({ network: "mainnet", storage });
    assert.deepEqual(later.seed, first.seed);
    assert.equal(s.calls, 3);
  });

  it("(b) accepts base64, hex and wallet-shaped results", async () => {
    for (const shape of [
      (sig: Uint8Array): unknown => Buffer.from(sig).toString("base64"),
      (sig: Uint8Array): unknown => Buffer.from(sig).toString("base64").replace(/=+$/, ""),
      (sig: Uint8Array): unknown => bytesToHex(sig),
      (sig: Uint8Array): unknown => ({ signedMessage: Buffer.from(sig).toString("base64") }),
      (sig: Uint8Array): unknown => ({ signature: sig }),
    ]) {
      const s = signer(SECRET, (digest) => shape(ed25519.sign(digest, SECRET)));
      const material = await keySource
        .signature(s)
        .resolve({ network: "mainnet", storage: new MemoryStore() });
      assert.equal(bytesToHex(material.seed), VECTORS.mainnet.seed);
    }
  });

  it("(b) verifies strictly: no small-order key, no key of a non-canonical encoding", () => {
    const le = (x: bigint): Uint8Array =>
      Uint8Array.from({ length: 32 }, (_, i) => Number((x >> BigInt(8 * i)) & 0xffn));
    // R the identity and S zero satisfy the cofactored equation for a key of small order, for
    // every message; ZIP 215 accepts them, RFC 8032's strict rules do not.
    const forged = Uint8Array.from([...le(1n), ...new Uint8Array(32)]);
    for (const y of [0n, 2n ** 255n - 19n]) {
      const key = StrKey.encodeEd25519PublicKey(Buffer.from(le(y)));
      assert.equal(verifySep53(key, signatureMessage("mainnet"), forged), false);
    }
  });

  it("(b) refuses a signature without the SEP-53 prefix", async () => {
    const raw = signer(SECRET, () => ed25519.sign(utf8(signatureMessage("testnet")), SECRET));
    await rejects(keySource.signature(raw).resolve(context), "signature_invalid");
    const other = signer(SECRET);
    const wrongKey = { ...other, publicKey: SEP5_TEST_5[1] as string };
    await rejects(keySource.signature(wrongKey).resolve(context), "signature_invalid");
    const short = signer(SECRET, () => new Uint8Array(63));
    await rejects(keySource.signature(short).resolve(context), "signature_invalid");
  });

  it("(b) maps a signer that declines to signer_rejected, whatever shape it declines in", async () => {
    for (const reply of [{ error: "User rejected the request" }, { signedMessage: null }, ""]) {
      const s = signer(SECRET, () => reply);
      await rejects(
        keySource.signature(s).resolve({ network: "mainnet", storage: new MemoryStore() }),
        "signer_rejected",
      );
    }
  });

  it("(b) refuses a signer that is not deterministic", async () => {
    // A valid signature with a different nonce: R' = r'B, S' = r' + H(R', A, M) a.
    const flaky = signer(SECRET, (digest, call) =>
      call === 0 ? ed25519.sign(digest, SECRET) : randomizedSignature(digest),
    );
    await rejects(
      keySource.signature(flaky).resolve({ network: "testnet", storage: new MemoryStore() }),
      "signature_not_deterministic",
    );
  });

  it("(b) refuses a seed that cannot open the state of an earlier session", async () => {
    const storage = new MemoryStore();
    let changed = false;
    const s = signer(SECRET, (digest) =>
      changed ? randomizedSignature(digest) : ed25519.sign(digest, SECRET),
    );
    await keySource.signature(s).resolve({ network: "testnet", storage });
    changed = true;
    await rejects(
      keySource.signature(s).resolve({ network: "testnet", storage }),
      "signature_seed_changed",
    );
    // the other network keeps its own record
    changed = false;
    await keySource.signature(s).resolve({ network: "mainnet", storage });
  });

  it("(b) signs each network's message and yields that network's vector seed", async () => {
    for (const network of NETWORKS) {
      const asked: string[] = [];
      const s = signer(SECRET);
      const signMessage = s.signMessage.bind(s);
      s.signMessage = async (message: string) => {
        asked.push(message);
        return signMessage(message);
      };
      const material = await keySource
        .signature(s)
        .resolve({ network, storage: new MemoryStore() });
      assert.deepEqual(new Set(asked), new Set([signatureMessage(network)]));
      assert.equal(bytesToHex(material.seed), VECTORS[network].seed);
    }
  });
});

// An Ed25519 signature over `digest` by SECRET with a random nonce, which verifies but differs
// from the RFC 8032 one.
function randomizedSignature(digest: Uint8Array): Uint8Array {
  const { Point, CURVE } = ed25519;
  const head = ed25519.utils.getExtendedPublicKey(SECRET);
  const r = BigInt("0x" + bytesToHex(crypto.getRandomValues(new Uint8Array(32)))) % CURVE.n;
  const R = Point.BASE.multiply(r === 0n ? 1n : r).toRawBytes();
  const k = ed25519.CURVE.hash(new Uint8Array([...R, ...head.pointBytes, ...digest]));
  const kInt = BigInt("0x" + bytesToHex(Uint8Array.from(k).reverse())) % CURVE.n;
  const s = ((r === 0n ? 1n : r) + kInt * head.scalar) % CURVE.n;
  const sBytes = hexToBytes(s.toString(16).padStart(64, "0")).reverse();
  return new Uint8Array([...R, ...sBytes]);
}

describe("sealed store", () => {
  it("encrypts records under names the backend cannot read", async () => {
    const backend = new MemoryStore();
    const key = new Uint8Array(32).fill(7);
    const store = new SealedStore(backend, key);
    await store.write("state", utf8("hello wallet"));
    assert.equal(backend.keys().length, 1);
    const location = backend.keys()[0] as string;
    assert.ok(!location.includes("state"));
    const raw = (await backend.get(location)) as Uint8Array;
    assert.ok(!Buffer.from(raw).includes(Buffer.from("hello")));
    assert.deepEqual(await store.read("state"), utf8("hello wallet"));
    assert.equal(await store.read("other"), undefined);
    await store.write("state", utf8("hello wallet"));
    assert.notDeepEqual(await backend.get(location), raw);
  });

  it("refuses a record under another key or moved to another name", async () => {
    const backend = new MemoryStore();
    const store = new SealedStore(backend, new Uint8Array(32).fill(1));
    await store.write("a", utf8("x"));
    const other = new SealedStore(backend, new Uint8Array(32).fill(2));
    assert.equal(await other.read("a"), undefined);
    await store.write("b", utf8("y"));
    const [first, second] = backend.keys() as [string, string];
    await backend.set(second, (await backend.get(first)) as Uint8Array);
    await assert.rejects(store.read("b"), (err: unknown) => err instanceof CyphrasError);
  });

  it("refuses a record moved to the same name in another scope", async () => {
    const backend = new MemoryStore();
    const key = new Uint8Array(32).fill(3);
    const one = new SealedStore(backend, key, "vault/one");
    const two = new SealedStore(backend, key, "vault/two");
    await one.write("state", utf8("one's"));
    await two.write("state", utf8("two's"));
    const [first, second] = backend.keys() as [string, string];
    await backend.set(second, (await backend.get(first)) as Uint8Array);
    await assert.rejects(two.read("state"), (err: unknown) => err instanceof CyphrasError);
    assert.deepEqual(await one.read("state"), utf8("one's"));
  });
});
