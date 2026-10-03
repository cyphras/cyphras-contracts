import { createHash } from "node:crypto";
import { bls12_381 } from "@noble/curves/bls12-381.js";
import { parseHex } from "./common.mjs";

// drand quicknet (scheme bls-unchained-g1-rfc9380), as its relays publish under /<hash>/info. A
// round is a BLS signature by the League of Entropy group key over the SHA-256 of the round
// number, and its randomness is the SHA-256 of that signature, so no relay can choose the value.
export const QUICKNET = {
  hash: "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971",
  publicKey:
    "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c" +
    "8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb" +
    "5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a",
  genesisTime: 1692803367,
  period: 3,
};
const DST = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";

export const RELAYS = [
  "https://api.drand.sh",
  "https://api2.drand.sh",
  "https://api3.drand.sh",
  "https://drand.cloudflare.com",
];
const MIN_RELAYS = 3;

export const roundTime = (round) =>
  new Date((QUICKNET.genesisTime + (round - 1) * QUICKNET.period) * 1000);

export const firstRoundAt = (date) =>
  Math.max(1, Math.ceil((date.getTime() / 1000 - QUICKNET.genesisTime) / QUICKNET.period) + 1);

export function parseRound(value) {
  const round = Number(value);
  if (!/^[1-9][0-9]*$/.test(String(value)) || !Number.isSafeInteger(round)) {
    throw new Error(`a drand round must be a positive integer, got "${value}"`);
  }
  return round;
}

export function verifyRound(round, signatureHex, randomnessHex) {
  const signature = Buffer.from(parseHex(signatureHex, 48, "the drand signature"), "hex");
  const randomness = parseHex(randomnessHex, 32, "the drand randomness");
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(round));
  const bls = bls12_381.shortSignatures;
  const point = bls.hash(createHash("sha256").update(message).digest(), DST);
  let valid;
  try {
    valid = bls.verify(signature, point, Buffer.from(QUICKNET.publicKey, "hex"));
  } catch {
    valid = false;
  }
  if (!valid) {
    throw new Error(`the signature of drand round ${round} does not verify under the quicknet key`);
  }
  if (createHash("sha256").update(signature).digest("hex") !== randomness) {
    throw new Error(`the randomness of drand round ${round} is not the hash of its signature`);
  }
}

// Every relay that answers must give the same round, and at least MIN_RELAYS must answer.
export async function fetchRound(round) {
  const answers = [];
  const failures = [];
  await Promise.all(
    RELAYS.map(async (relay) => {
      try {
        const res = await fetch(`${relay}/${QUICKNET.hash}/public/${round}`, {
          signal: AbortSignal.timeout(20_000),
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const { round: got, signature, randomness } = await res.json();
        answers.push({ relay, got, signature, randomness });
      } catch (e) {
        failures.push(`${relay}: ${e.message}`);
      }
    }),
  );
  if (answers.length < MIN_RELAYS) {
    throw new Error(
      `only ${answers.length} drand relays returned round ${round}, ${MIN_RELAYS} are needed ` +
        `(is the round produced yet?)\n  ${failures.join("\n  ")}`,
    );
  }
  const [first] = answers;
  for (const a of answers) {
    if (a.got !== round || a.signature !== first.signature || a.randomness !== first.randomness) {
      throw new Error(`drand relays disagree on round ${round}: ${first.relay} and ${a.relay}`);
    }
  }
  verifyRound(round, first.signature, first.randomness);
  return {
    round,
    time: roundTime(round).toISOString(),
    randomness: first.randomness,
    signature: first.signature,
    relays: answers.map((a) => a.relay).sort(),
  };
}
