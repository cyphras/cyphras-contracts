import { ed25519 } from "@noble/curves/ed25519";
import { sha256, sha512 } from "@noble/hashes/sha2";
import { base64 } from "@scure/base";
import { generateMnemonic, mnemonicToSeed, validateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english";
import { StrKey } from "@stellar/stellar-base";
import { bytesToHex, concatBytes, equalBytes, hexToBytes, utf8 } from "./bytes.ts";
import { fail } from "./errors.ts";
import { type Network, SEED_LENGTH, checkAccount, deriveStoreKey } from "./keys.ts";
import { type KeyValueStore, openRecord, sealRecord } from "./storage.ts";

/**
 * The message a Stellar wallet signs under SEP-53 to derive a mode (b) private account: ASCII,
 * lines separated by a single LF, no trailing newline.
 */
export const SIGNATURE_MESSAGE = [
  "Cyphras private account v2",
  "",
  "Signing this message creates the key to a Cyphras private balance.",
  "Anyone who obtains this signature can spend that balance.",
  "Only sign it in an app you trust.",
].join("\n");

const SEP53_PREFIX = "Stellar Signed Message:\n";
const SIG_SEED_LABEL = utf8("cyphras/v2/sig-seed");
const MARKER = utf8("cyphras/v2/sig-marker");

export function sep53Digest(message: string): Uint8Array {
  return sha256(concatBytes(utf8(SEP53_PREFIX), utf8(message)));
}

// Strict RFC 8032 verification: a non-canonical S would be a second encoding of one signature,
// and so a second seed.
export function verifySep53(publicKey: string, message: string, signature: Uint8Array): boolean {
  if (!StrKey.isValidEd25519PublicKey(publicKey) || signature.length !== 64) return false;
  try {
    const key = Uint8Array.from(StrKey.decodeEd25519PublicKey(publicKey));
    return ed25519.verify(signature, sep53Digest(message), key, { zip215: false });
  } catch {
    return false;
  }
}

export function signatureSeed(signature: Uint8Array): Uint8Array {
  return sha512(concatBytes(SIG_SEED_LABEL, signature));
}

/** What a key source yields: the 64-byte seed and the account index the keys derive from. */
export interface SeedMaterial {
  readonly seed: Uint8Array;
  readonly account: number;
}

/** What a key source may read while it resolves: the network and the wallet's store. */
export interface KeySourceContext {
  readonly network: Network;
  readonly storage: KeyValueStore;
}

/** One of the three ways to obtain the seed of a private account (sdk.md, Key sources). */
export interface KeySource {
  readonly mode: "mnemonic" | "signature" | "random";
  resolve(context: KeySourceContext): Promise<SeedMaterial>;
}

/** A random key source, whose mnemonic the app must show to the user as the backup. */
export interface RandomKeySource extends KeySource {
  revealMnemonic(): string;
}

/**
 * A Stellar wallet that signs messages under SEP-53 with the account's ed25519 key. The result
 * may be the 64-byte signature as bytes, base64 or hex, or an object carrying it as
 * `signedMessage` or `signature`.
 */
export interface MessageSigner {
  readonly publicKey: string;
  signMessage(message: string): Promise<unknown>;
}

function normalizeMnemonic(words: string | readonly string[]): string {
  const text = typeof words === "string" ? words : words.join(" ");
  const normalized = text.trim().split(/\s+/).join(" ");
  if (!validateMnemonic(normalized, wordlist)) {
    fail("invalid_mnemonic", "the mnemonic is not a valid English BIP39 mnemonic");
  }
  return normalized;
}

function mnemonicSource(
  mode: "mnemonic" | "random",
  mnemonic: string,
  passphrase: string,
  account: number,
): KeySource {
  checkAccount(account);
  return {
    mode,
    async resolve(): Promise<SeedMaterial> {
      const seed = await mnemonicToSeed(mnemonic, passphrase);
      return { seed: Uint8Array.from(seed), account };
    },
  };
}

function signatureBytes(value: unknown, depth = 0): Uint8Array | undefined {
  if (value instanceof Uint8Array) return value.length === 64 ? Uint8Array.from(value) : undefined;
  if (typeof value === "string") {
    if (/^[0-9a-fA-F]{128}$/.test(value)) return hexToBytes(value.toLowerCase());
    for (const candidate of [value, value + "=", value + "=="]) {
      try {
        const bytes = base64.decode(candidate);
        if (bytes.length === 64) return bytes;
      } catch {
        // not this padding
      }
    }
    return undefined;
  }
  if (depth === 0 && typeof value === "object" && value !== null) {
    const record = value as Record<string, unknown>;
    return signatureBytes(record["signedMessage"] ?? record["signature"], 1);
  }
  return undefined;
}

async function signedSeedMessage(signer: MessageSigner): Promise<Uint8Array> {
  const signature = signatureBytes(await signer.signMessage(SIGNATURE_MESSAGE));
  if (signature === undefined) {
    fail("signature_invalid", "the wallet did not return a 64-byte ed25519 signature");
  }
  if (!verifySep53(signer.publicKey, SIGNATURE_MESSAGE, signature)) {
    signature.fill(0);
    fail(
      "signature_invalid",
      "the signature does not verify under SEP-53; this wallet cannot derive a private account",
    );
  }
  return signature;
}

// The local record that ties a public key to the seed of its first session. Its location is
// derived from the public key, which this store's owner already knows.
function markerLocation(network: Network, publicKey: string): string {
  const id = sha256(utf8(`cyphras/v2/sig-marker/${network}/${publicKey}`));
  return "cyphras/v2/sig/" + bytesToHex(id.subarray(0, 20));
}

function signatureSource(signer: MessageSigner): KeySource {
  return {
    mode: "signature",
    async resolve({ network, storage }: KeySourceContext): Promise<SeedMaterial> {
      if (!StrKey.isValidEd25519PublicKey(signer.publicKey)) {
        fail("signature_invalid", "mode (b) needs an ed25519 account (G...) as the signer");
      }
      const location = markerLocation(network, signer.publicKey);
      const marker = await storage.get(location);
      const first = await signedSeedMessage(signer);
      if (marker === undefined) {
        // RFC 8032 signatures are deterministic, but not every signer follows it; a second
        // request shows whether this one does before any funds depend on it.
        const second = await signedSeedMessage(signer);
        const same = equalBytes(first, second);
        second.fill(0);
        if (!same) {
          first.fill(0);
          fail(
            "signature_not_deterministic",
            "the wallet signed the message twice with different results; mode (b) is unavailable",
          );
        }
      }
      const seed = signatureSeed(first);
      first.fill(0);
      const storeKey = deriveStoreKey(seed, network, 0);
      const aad = utf8(signer.publicKey);
      if (marker === undefined) {
        await storage.set(location, sealRecord(storeKey, aad, MARKER));
      } else {
        const opened = openRecord(storeKey, aad, marker);
        if (opened === undefined || !equalBytes(opened, MARKER)) {
          seed.fill(0);
          fail(
            "signature_seed_changed",
            "this signature gives a different seed than in earlier sessions; continuing would " +
              "strand the funds sent to the earlier addresses",
          );
        }
      }
      return { seed, account: 0 };
    },
  };
}

/** The key sources of sdk.md: (a) mnemonic, (b) signature and (c) random. */
export const keySource = {
  /**
   * Mode (a): the BIP39 seed of the wallet's mnemonic and passphrase, at the SEP-0005 index of
   * the Stellar account, so every wallet that implements the spec restores the same balance.
   */
  mnemonic(
    words: string | readonly string[],
    options: { readonly passphrase?: string; readonly account: number },
  ): KeySource {
    return mnemonicSource(
      "mnemonic",
      normalizeMnemonic(words),
      options.passphrase ?? "",
      options.account,
    );
  },

  /**
   * Mode (b): SHA-512("cyphras/v2/sig-seed" || signature) of the SEP-53 signature of
   * SIGNATURE_MESSAGE, account 0. The signature is a secret: anyone who obtains it can spend
   * the balance.
   */
  signature(signer: MessageSigner): KeySource {
    return signatureSource(signer);
  },

  /**
   * Mode (c): a new 24-word mnemonic with an empty passphrase, account 0. Importing the
   * mnemonic into a wallet restores the balance under mode (a).
   */
  random(): RandomKeySource {
    const mnemonic = generateMnemonic(wordlist, 256);
    return { ...mnemonicSource("random", mnemonic, "", 0), revealMnemonic: () => mnemonic };
  },
};

export function checkSeed(material: SeedMaterial): void {
  if (material.seed.length !== SEED_LENGTH) fail("invalid_argument", "the seed must be 64 bytes");
  checkAccount(material.account);
}
