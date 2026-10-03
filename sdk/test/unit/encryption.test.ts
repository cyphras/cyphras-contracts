import assert from "node:assert/strict";
import { createCipheriv, createHash } from "node:crypto";
import { describe, it } from "node:test";
import { mnemonicToSeedSync } from "@scure/bip39";
import { decodeAddress } from "../../src/address.ts";
import { L, packPoint, scalarMul } from "../../src/babyjub.ts";
import { bigIntToBytesLE, bytesToHex, hexToBytes } from "../../src/bytes.ts";
import {
  AddressCache,
  CIPHERTEXT_LENGTH,
  decryptIncoming,
  encryptOutput,
  ephemeralKey,
  recoverOutgoing,
} from "../../src/encryption.ts";
import { defaultAddressKey, deriveSpendingKeys } from "../../src/keys.ts";
import { noteCommitment, randomFieldElement, randomScalar } from "../../src/notes.ts";
import { encryptionVectors } from "../../scripts/vectors.ts";
import { MNEMONIC, sdkVectors } from "../helpers.ts";

interface EncryptionVectors {
  outputs: {
    recipient_account: number;
    address: string;
    d: string;
    value: string;
    rcm: string;
    cm: string;
    esk: string;
    epk: string;
    shared_point: string;
    view_tag: number;
    k_enc: string;
    enc_plaintext: string;
    c_enc: string;
    ock: string;
    out_plaintext: string;
    c_out: string;
    ciphertext: string;
  }[];
}

const VECTORS = sdkVectors<EncryptionVectors>("encryption.json");
const seed = mnemonicToSeedSync(MNEMONIC);
const accounts = [deriveSpendingKeys(seed, "mainnet", 0), deriveSpendingKeys(seed, "mainnet", 1)];
const sender = accounts[0] as (typeof accounts)[0];

// HChaCha20 and the IETF ChaCha20-Poly1305 of node:crypto give XChaCha20-Poly1305 without the
// library the SDK uses.
function hchacha20(key: Uint8Array, nonce16: Uint8Array): Uint8Array {
  const word = (b: Uint8Array, i: number): number =>
    ((b[i] as number) |
      ((b[i + 1] as number) << 8) |
      ((b[i + 2] as number) << 16) |
      ((b[i + 3] as number) << 24)) >>>
    0;
  const s = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];
  for (let i = 0; i < 8; i++) s.push(word(key, 4 * i));
  for (let i = 0; i < 4; i++) s.push(word(nonce16, 4 * i));
  const rotl = (v: number, n: number): number => ((v << n) | (v >>> (32 - n))) >>> 0;
  const qr = (a: number, b: number, c: number, d: number): void => {
    s[a] = ((s[a] as number) + (s[b] as number)) >>> 0;
    s[d] = rotl((s[d] as number) ^ (s[a] as number), 16);
    s[c] = ((s[c] as number) + (s[d] as number)) >>> 0;
    s[b] = rotl((s[b] as number) ^ (s[c] as number), 12);
    s[a] = ((s[a] as number) + (s[b] as number)) >>> 0;
    s[d] = rotl((s[d] as number) ^ (s[a] as number), 8);
    s[c] = ((s[c] as number) + (s[d] as number)) >>> 0;
    s[b] = rotl((s[b] as number) ^ (s[c] as number), 7);
  };
  for (let round = 0; round < 10; round++) {
    qr(0, 4, 8, 12);
    qr(1, 5, 9, 13);
    qr(2, 6, 10, 14);
    qr(3, 7, 11, 15);
    qr(0, 5, 10, 15);
    qr(1, 6, 11, 12);
    qr(2, 7, 8, 13);
    qr(3, 4, 9, 14);
  }
  const out = new Uint8Array(32);
  [0, 1, 2, 3, 12, 13, 14, 15].forEach((w, i) => {
    const v = s[w] as number;
    out.set([v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, (v >>> 24) & 0xff], 4 * i);
  });
  return out;
}

function sealWithZeroNonce(key: Uint8Array, plaintext: Uint8Array): string {
  const cipher = createCipheriv(
    "chacha20-poly1305",
    hchacha20(key, new Uint8Array(16)),
    new Uint8Array(12),
    {
      authTagLength: 16,
    },
  );
  const body = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
  return body.toString("hex");
}

const sha256Hex = (...parts: (string | Uint8Array)[]): string => {
  const h = createHash("sha256");
  for (const p of parts) h.update(typeof p === "string" ? Buffer.from(p, "ascii") : p);
  return h.digest("hex");
};

describe("note encryption", () => {
  it("encryption.json matches a fresh run", () => {
    assert.deepEqual(VECTORS, JSON.parse(JSON.stringify(encryptionVectors())));
  });

  for (const [i, v] of VECTORS.outputs.entries()) {
    describe(`output ${i} (value ${v.value})`, () => {
      const recipient = accounts[v.recipient_account] as typeof sender;
      const address = decodeAddress("mainnet", v.address);
      const blob = hexToBytes(v.ciphertext);
      const cm = BigInt(v.cm);

      it("agrees with an independent SHA-256 and XChaCha20-Poly1305", () => {
        const epk = hexToBytes(v.epk);
        const shared = hexToBytes(v.shared_point);
        assert.equal(bytesToHex(packPoint(scalarMul(address.gd, BigInt(v.esk)))), v.epk);
        assert.equal(bytesToHex(packPoint(scalarMul(address.pkd, BigInt(v.esk)))), v.shared_point);
        assert.equal(
          parseInt(sha256Hex("cyphras/v2/tag", shared, epk).slice(0, 2), 16),
          v.view_tag,
        );
        assert.equal(sha256Hex("cyphras/v2/enc", shared, epk), v.k_enc);
        const ock = sha256Hex("cyphras/v2/out", sender.ovk, bigIntToBytesLE(cm, 32), epk);
        assert.equal(ock, v.ock);
        assert.equal(sealWithZeroNonce(hexToBytes(v.k_enc), hexToBytes(v.enc_plaintext)), v.c_enc);
        assert.equal(sealWithZeroNonce(hexToBytes(v.ock), hexToBytes(v.out_plaintext)), v.c_out);
        assert.equal(
          v.ciphertext,
          v.epk + v.view_tag.toString(16).padStart(2, "0") + v.c_enc + v.c_out,
        );
        assert.equal(blob.length, CIPHERTEXT_LENGTH);
      });

      it("is found by the recipient's incoming viewing key", () => {
        const note = decryptIncoming(recipient, cm, blob);
        assert.ok(note !== undefined);
        assert.equal(note.value, BigInt(v.value));
        assert.equal(note.rcm, BigInt(v.rcm));
        assert.equal(bytesToHex(note.d), v.d);
        assert.deepEqual([note.gd, note.q, note.pkd], [address.gd, address.q, address.pkd]);
      });

      it("is recovered by the sender's outgoing viewing key", () => {
        const note = recoverOutgoing(sender.ovk, cm, blob);
        assert.ok(note !== undefined);
        assert.equal(note.esk, BigInt(v.esk));
        assert.equal(note.value, BigInt(v.value));
        assert.deepEqual(note.pkd, address.pkd);
      });

      it("is not found by anyone else", () => {
        const other = accounts[1 - v.recipient_account] as typeof sender;
        assert.equal(decryptIncoming(other, cm, blob), undefined);
        assert.equal(recoverOutgoing(accounts[1]?.ovk as Uint8Array, cm, blob), undefined);
      });

      it("is bound to its commitment", () => {
        assert.equal(decryptIncoming(recipient, cm + 1n, blob), undefined);
        assert.equal(recoverOutgoing(sender.ovk, cm + 1n, blob), undefined);
      });
    });
  }

  it("rejects every single-byte change", () => {
    const v = VECTORS.outputs[1] as EncryptionVectors["outputs"][0];
    const recipient = accounts[v.recipient_account] as typeof sender;
    const blob = hexToBytes(v.ciphertext);
    // The recipient reads epk, the view tag and C_enc; the sender reads everything but the tag.
    for (let i = 0; i < blob.length; i++) {
      const changed = Uint8Array.from(blob);
      changed[i] = (changed[i] as number) ^ 0x01;
      if (i < 101) {
        assert.equal(decryptIncoming(recipient, BigInt(v.cm), changed), undefined, `byte ${i}`);
      }
      if (i !== 32) {
        assert.equal(recoverOutgoing(sender.ovk, BigInt(v.cm), changed), undefined, `byte ${i}`);
      }
    }
  });

  it("refuses a blob of the wrong length", () => {
    const v = VECTORS.outputs[0] as EncryptionVectors["outputs"][0];
    const blob = hexToBytes(v.ciphertext);
    assert.equal(
      decryptIncoming(accounts[1] as typeof sender, BigInt(v.cm), blob.subarray(1)),
      undefined,
    );
    assert.equal(ephemeralKey(blob.subarray(1)), undefined);
  });

  it("round-trips random notes through a cached address", () => {
    const recipient = accounts[1] as typeof sender;
    const address = defaultAddressKey(recipient);
    const cache = new AddressCache(recipient);
    for (let i = 0; i < 8; i++) {
      const note = { ...address, value: BigInt(i * 1_000_003), rcm: randomFieldElement() };
      const esk = randomScalar();
      assert.ok(esk > 0n && esk < L);
      const blob = encryptOutput(note, sender.ovk, esk);
      const found = decryptIncoming(recipient, noteCommitment(note), blob, cache);
      assert.equal(found?.value, note.value);
      assert.deepEqual(ephemeralKey(blob), scalarMul(address.gd, esk));
    }
  });

  it("refuses an esk outside [1, L)", () => {
    const note = { ...defaultAddressKey(sender), value: 1n, rcm: 1n };
    assert.throws(() => encryptOutput(note, sender.ovk, 0n));
    assert.throws(() => encryptOutput(note, sender.ovk, L));
  });
});
