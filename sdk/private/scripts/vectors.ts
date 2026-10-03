// Writes the SDK's test vectors to test/vectors/. Every value derives from the published BIP39 test
// mnemonic and fixed labels, so the files regenerate byte for byte; the unit tests compare them
// with a fresh run and check the primitives against independent implementations.
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { xchacha20poly1305 } from "@noble/ciphers/chacha";
import { ed25519 } from "@noble/curves/ed25519";
import { hmac } from "@noble/hashes/hmac";
import { sha256, sha512 } from "@noble/hashes/sha2";
import { base64 } from "@scure/base";
import { mnemonicToSeedSync } from "@scure/bip39";
import { StrKey } from "@stellar/stellar-base";
import { encodeAddress } from "../src/address.ts";
import { L, packPoint, scalarMul } from "../src/babyjub.ts";
import {
  bigIntToBytesLE,
  bytesToBigIntBE,
  bytesToHex,
  concatBytes,
  toHex32,
  utf8,
} from "../src/bytes.ts";
import { encryptOutput } from "../src/encryption.ts";
import { P } from "../src/field.ts";
import { addressKeyAt, defaultAddressKey, deriveSpendingKeys } from "../src/keys.ts";
import { SIGNATURE_MESSAGE, sep53Digest, signatureSeed } from "../src/keysource.ts";
import { noteCommitment } from "../src/notes.ts";

export const MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

const FORMAT =
  "Field elements and scalars are 0x-prefixed 32-byte big-endian hex. Byte strings are " +
  "unprefixed hex. Points are packed with packPoint.";

const labelled = (label: string, modulus: bigint): bigint =>
  bytesToBigIntBE(sha512(utf8(label))) % modulus;

const ENCRYPTION_CASES = [
  { recipient: 1, index: 0, value: 0n },
  { recipient: 1, index: 2, value: 1n },
  { recipient: 0, index: 0, value: 250_000_000n },
  { recipient: 1, index: 1, value: (1n << 64n) - 1n },
];

export function encryptionVectors(): object {
  const seed = mnemonicToSeedSync(MNEMONIC);
  const sender = deriveSpendingKeys(seed, "mainnet", 0);
  const accounts = [sender, deriveSpendingKeys(seed, "mainnet", 1)];
  const zeroNonce = new Uint8Array(24);
  const outputs = ENCRYPTION_CASES.map(({ recipient, index, value }, i) => {
    const owner = accounts[recipient] as typeof sender;
    const address = addressKeyAt(owner, index);
    if (address === undefined) throw new Error("invalid diversifier in the vector cases");
    const rcm = labelled(`cyphras/v2/vectors/enc-rcm/${i}`, P);
    const esk = labelled(`cyphras/v2/vectors/esk/${i}`, L - 1n) + 1n;
    const note = { d: address.d, gd: address.gd, pkd: address.pkd, value, rcm };
    const cm = noteCommitment(note);
    const epk = packPoint(scalarMul(address.gd, esk));
    const shared = packPoint(scalarMul(address.pkd, esk));
    const tag = sha256(concatBytes(utf8("cyphras/v2/tag"), shared, epk))[0] as number;
    const kEnc = sha256(concatBytes(utf8("cyphras/v2/enc"), shared, epk));
    const plaintext = concatBytes(
      Uint8Array.of(0x02),
      address.d,
      bigIntToBytesLE(value, 8),
      bigIntToBytesLE(rcm, 32),
    );
    const cEnc = xchacha20poly1305(kEnc, zeroNonce).encrypt(plaintext);
    const ock = sha256(
      concatBytes(utf8("cyphras/v2/out"), sender.ovk, bigIntToBytesLE(cm, 32), epk),
    );
    const outPlaintext = concatBytes(packPoint(address.pkd), bigIntToBytesLE(esk, 32));
    const cOut = xchacha20poly1305(ock, zeroNonce).encrypt(outPlaintext);
    const ciphertext = concatBytes(epk, Uint8Array.of(tag), cEnc, cOut);
    if (bytesToHex(encryptOutput(note, sender.ovk, esk)) !== bytesToHex(ciphertext)) {
      throw new Error("encryptOutput disagrees with the formulas computed here step by step");
    }
    return {
      recipient_account: recipient,
      diversifier_index: index,
      address: encodeAddress("mainnet", address.d, address.pkd),
      d: bytesToHex(address.d),
      value: value.toString(),
      rcm: toHex32(rcm),
      cm: toHex32(cm),
      esk: toHex32(esk),
      epk: bytesToHex(epk),
      shared_point: bytesToHex(shared),
      view_tag: tag,
      k_enc: bytesToHex(kEnc),
      enc_plaintext: bytesToHex(plaintext),
      c_enc: bytesToHex(cEnc),
      ock: bytesToHex(ock),
      out_plaintext: bytesToHex(outPlaintext),
      c_out: bytesToHex(cOut),
      ciphertext: bytesToHex(ciphertext),
    };
  });
  return {
    description: "Output ciphertext vectors of the note encryption, with every intermediate value.",
    format: FORMAT,
    derivation:
      'rcm_i = SHA-512("cyphras/v2/vectors/enc-rcm/" || i) mod p and ' +
      'esk_i = SHA-512("cyphras/v2/vectors/esk/" || i) mod (L - 1) + 1, for these vectors only',
    mnemonic: MNEMONIC,
    network: "mainnet",
    sender_account: 0,
    sender_ovk: bytesToHex(sender.ovk),
    outputs,
  };
}

// SLIP-0010 ed25519 derivation along hardened indices, as SEP-0005 uses for Stellar accounts.
export function slip10Ed25519(seed: Uint8Array, path: readonly number[]): Uint8Array {
  let node = hmac(sha512, utf8("ed25519 seed"), seed);
  for (const index of path) {
    const hardened = new Uint8Array(4);
    new DataView(hardened.buffer).setUint32(0, (index | 0x80000000) >>> 0);
    node = hmac(
      sha512,
      node.subarray(32),
      concatBytes(Uint8Array.of(0), node.subarray(0, 32), hardened),
    );
  }
  return node.slice(0, 32);
}

export const SEP5_ACCOUNT_0 = [44, 148, 0];

export function sigSeedVectors(): object {
  const secret = slip10Ed25519(mnemonicToSeedSync(MNEMONIC), SEP5_ACCOUNT_0);
  const account = StrKey.encodeEd25519PublicKey(Buffer.from(ed25519.getPublicKey(secret)));
  const digest = sep53Digest(SIGNATURE_MESSAGE);
  const signature = ed25519.sign(digest, secret);
  const seed = signatureSeed(signature);
  const address = (network: "mainnet" | "testnet"): string => {
    const key = defaultAddressKey(deriveSpendingKeys(seed, network, 0));
    return encodeAddress(network, key.d, key.pkd);
  };
  return {
    description:
      "Signature seed vectors for key source (b): the message, the SEP-53 digest a Stellar " +
      "wallet signs, the signature of a test account and the seed it yields.",
    derivation:
      'seed = SHA-512("cyphras/v2/sig-seed" || signature), with the 64-byte signature R || S',
    message: SIGNATURE_MESSAGE,
    message_length: utf8(SIGNATURE_MESSAGE).length,
    message_sha256: bytesToHex(sha256(utf8(SIGNATURE_MESSAGE))),
    sep53_digest: bytesToHex(digest),
    signer: {
      mnemonic: MNEMONIC,
      path: "m/44'/148'/0'",
      account,
    },
    signature: bytesToHex(signature),
    signature_base64: base64.encode(signature),
    seed: bytesToHex(seed),
    default_addresses: { mainnet: address("mainnet"), testnet: address("testnet") },
  };
}

const OUT = join(import.meta.dirname, "..", "test", "vectors");

if (process.argv[1] === import.meta.filename) {
  for (const [name, vectors] of [
    ["encryption.json", encryptionVectors()],
    ["sig-seed.json", sigSeedVectors()],
  ] as const) {
    writeFileSync(join(OUT, name), JSON.stringify(vectors, null, 2) + "\n");
    console.log(`wrote ${join(OUT, name)}`);
  }
}
