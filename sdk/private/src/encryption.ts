import { xchacha20poly1305 } from "@noble/ciphers/chacha";
import { sha256 } from "@noble/hashes/sha2";
import {
  L,
  type Point,
  equalPoints,
  isIdentity,
  isPrimeOrderPoint,
  packPoint,
  scalarMul,
  unpackPoint,
} from "./babyjub.ts";
import { bigIntToBytesLE, bytesToBigIntLE, bytesToHex, concatBytes, utf8 } from "./bytes.ts";
import { P } from "./field.ts";
import { DIVERSIFIER_LENGTH, type IncomingKeys, diversifyHash } from "./keys.ts";
import { noteCommitment } from "./notes.ts";

export const CIPHERTEXT_LENGTH = 181;
const PLAINTEXT_VERSION = 0x02;
const ENC_PLAINTEXT_LENGTH = 1 + DIVERSIFIER_LENGTH + 8 + 32;
const OUT_PLAINTEXT_LENGTH = 64;
const EPK = [0, 32] as const;
const TAG_OFFSET = 32;
const C_ENC = [33, 33 + ENC_PLAINTEXT_LENGTH + 16] as const;
const C_OUT = [C_ENC[1], CIPHERTEXT_LENGTH] as const;
// Both keys are single use: k_enc depends on the fresh epk, and ock on epk and cm.
const ZERO_NONCE = new Uint8Array(24);

const LABEL_TAG = utf8("cyphras/v2/tag");
const LABEL_ENC = utf8("cyphras/v2/enc");
const LABEL_OUT = utf8("cyphras/v2/out");

export interface OutputNote {
  readonly d: Uint8Array;
  readonly gd: Point;
  readonly pkd: Point;
  readonly value: bigint;
  readonly rcm: bigint;
}

export interface DecryptedNote extends OutputNote {
  readonly q: Point;
  readonly cm: bigint;
}

export interface RecoveredNote extends DecryptedNote {
  readonly esk: bigint;
}

function viewTag(sharedPacked: Uint8Array, epkPacked: Uint8Array): number {
  return sha256(concatBytes(LABEL_TAG, sharedPacked, epkPacked))[0] as number;
}

function encryptionKey(sharedPacked: Uint8Array, epkPacked: Uint8Array): Uint8Array {
  return sha256(concatBytes(LABEL_ENC, sharedPacked, epkPacked));
}

function outgoingKey(ovk: Uint8Array, cm: bigint, epkPacked: Uint8Array): Uint8Array {
  return sha256(concatBytes(LABEL_OUT, ovk, bigIntToBytesLE(cm, 32), epkPacked));
}

function open(key: Uint8Array, ciphertext: Uint8Array): Uint8Array | undefined {
  try {
    return xchacha20poly1305(key, ZERO_NONCE).decrypt(ciphertext);
  } catch {
    return undefined;
  }
}

function seal(key: Uint8Array, plaintext: Uint8Array): Uint8Array {
  return xchacha20poly1305(key, ZERO_NONCE).encrypt(plaintext);
}

// Builds the 181-byte ciphertext of an output. `esk` must be fresh and uniform in [1, L).
export function encryptOutput(note: OutputNote, ovk: Uint8Array, esk: bigint): Uint8Array {
  if (esk <= 0n || esk >= L) throw new RangeError("esk must be in [1, L)");
  if (note.d.length !== DIVERSIFIER_LENGTH) throw new RangeError("d must be 11 bytes");
  const cm = noteCommitment(note);
  const epkPacked = packPoint(scalarMul(note.gd, esk));
  const sharedPacked = packPoint(scalarMul(note.pkd, esk));
  const plaintext = concatBytes(
    Uint8Array.of(PLAINTEXT_VERSION),
    note.d,
    bigIntToBytesLE(note.value, 8),
    bigIntToBytesLE(note.rcm, 32),
  );
  const outgoing = concatBytes(packPoint(note.pkd), bigIntToBytesLE(esk, 32));
  return concatBytes(
    epkPacked,
    Uint8Array.of(viewTag(sharedPacked, epkPacked)),
    seal(encryptionKey(sharedPacked, epkPacked), plaintext),
    seal(outgoingKey(ovk, cm, epkPacked), outgoing),
  );
}

interface EncPlaintext {
  d: Uint8Array;
  value: bigint;
  rcm: bigint;
}

function parsePlaintext(plaintext: Uint8Array | undefined): EncPlaintext | undefined {
  if (plaintext === undefined || plaintext.length !== ENC_PLAINTEXT_LENGTH) return undefined;
  if (plaintext[0] !== PLAINTEXT_VERSION) return undefined;
  const rcm = bytesToBigIntLE(plaintext.subarray(1 + DIVERSIFIER_LENGTH + 8));
  if (rcm >= P) return undefined;
  return {
    d: plaintext.slice(1, 1 + DIVERSIFIER_LENGTH),
    value: bytesToBigIntLE(plaintext.subarray(1 + DIVERSIFIER_LENGTH, 1 + DIVERSIFIER_LENGTH + 8)),
    rcm,
  };
}

// The address keys of the wallet's own diversifiers, cached because each costs a scalar
// multiplication and a wallet receives most notes at a few addresses.
export class AddressCache {
  readonly #keys: IncomingKeys;
  readonly #entries = new Map<string, { gd: Point; q: Point; pkd: Point } | null>();

  constructor(keys: IncomingKeys) {
    this.#keys = keys;
  }

  get(d: Uint8Array): { gd: Point; q: Point; pkd: Point } | undefined {
    const id = bytesToHex(d);
    let entry = this.#entries.get(id);
    if (entry === undefined) {
      const diversified = diversifyHash(d);
      entry =
        diversified === undefined
          ? null
          : { ...diversified, pkd: scalarMul(diversified.gd, this.#keys.ivk) };
      this.#entries.set(id, entry);
    }
    return entry ?? undefined;
  }
}

// Trial decryption with the incoming viewing key. epk is checked to be of prime order before the
// view tag, so every output costs the same work up to the tag, whether or not it is ours.
export function decryptIncoming(
  keys: IncomingKeys,
  cm: bigint,
  blob: Uint8Array,
  cache: AddressCache = new AddressCache(keys),
): DecryptedNote | undefined {
  if (blob.length !== CIPHERTEXT_LENGTH) return undefined;
  const epkPacked = blob.subarray(...EPK);
  const epk = unpackPoint(epkPacked);
  if (epk === undefined || isIdentity(epk)) return undefined;
  if (!isPrimeOrderPoint(epk)) return undefined;
  const sharedPacked = packPoint(scalarMul(epk, keys.ivk));
  if (viewTag(sharedPacked, epkPacked) !== blob[TAG_OFFSET]) return undefined;
  const parsed = parsePlaintext(
    open(encryptionKey(sharedPacked, epkPacked), blob.subarray(...C_ENC)),
  );
  if (parsed === undefined) return undefined;
  const address = cache.get(parsed.d);
  if (address === undefined) return undefined;
  const note = { ...parsed, gd: address.gd, pkd: address.pkd };
  // A ciphertext that decrypts but does not match the commitment on chain is not a note.
  if (noteCommitment(note) !== cm) return undefined;
  return { ...note, q: address.q, cm };
}

// Recovery of an output the wallet built, with its outgoing viewing key.
export function recoverOutgoing(
  ovk: Uint8Array,
  cm: bigint,
  blob: Uint8Array,
): RecoveredNote | undefined {
  if (blob.length !== CIPHERTEXT_LENGTH) return undefined;
  const epkPacked = blob.subarray(...EPK);
  const outgoing = open(outgoingKey(ovk, cm, epkPacked), blob.subarray(...C_OUT));
  if (outgoing === undefined || outgoing.length !== OUT_PLAINTEXT_LENGTH) return undefined;
  const pkd = unpackPoint(outgoing.subarray(0, 32));
  const esk = bytesToBigIntLE(outgoing.subarray(32));
  if (pkd === undefined || !isPrimeOrderPoint(pkd) || esk === 0n || esk >= L) return undefined;
  const sharedPacked = packPoint(scalarMul(pkd, esk));
  const parsed = parsePlaintext(
    open(encryptionKey(sharedPacked, epkPacked), blob.subarray(...C_ENC)),
  );
  if (parsed === undefined) return undefined;
  const diversified = diversifyHash(parsed.d);
  if (diversified === undefined) return undefined;
  const epk = unpackPoint(epkPacked);
  if (epk === undefined || !equalPoints(epk, scalarMul(diversified.gd, esk))) return undefined;
  const note = { ...parsed, gd: diversified.gd, pkd };
  if (noteCommitment(note) !== cm) return undefined;
  return { ...note, q: diversified.q, cm, esk };
}

// The ephemeral key of a ciphertext, which a payment disclosure checks against esk * g_d.
export function ephemeralKey(blob: Uint8Array): Point | undefined {
  if (blob.length !== CIPHERTEXT_LENGTH) return undefined;
  return unpackPoint(blob.subarray(...EPK));
}
