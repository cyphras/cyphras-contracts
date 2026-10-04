import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex } from "./bytes.ts";
import { fail } from "./errors.ts";
import { type VerifyingKey, parseVerifyingKey } from "./groth16.ts";
import type { CircuitArtifacts, CircuitPins } from "./prover.ts";

/** The circuit artifacts: the witness generator, the proving key and the verifying key. */
export type ArtifactName = "wasm" | "zkey" | "vkey";

/**
 * Where the circuit artifacts are read from, for example files shipped with an extension or fetched
 * from the release. Every file is checked against its pinned SHA-256 before use: the verifying key
 * by the SDK, and the witness generator and the proving key by the prover that proves with them.
 */
export interface ArtifactSource {
  load(name: ArtifactName): Promise<Uint8Array>;
}

/** The SHA-256 of each artifact, as lowercase hex. */
export type ArtifactPins = Readonly<Record<ArtifactName, string>>;

const SHA256_HEX = /^[0-9a-f]{64}$/;

export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const subtle = globalThis.crypto?.subtle;
  if (subtle !== undefined) {
    return bytesToHex(new Uint8Array(await subtle.digest("SHA-256", bytes as BufferSource)));
  }
  return bytesToHex(sha256(bytes));
}

export function checkArtifactPins(pins: ArtifactPins): void {
  for (const name of ["wasm", "zkey", "vkey"] as const) {
    if (!SHA256_HEX.test(pins[name]))
      fail("deployment_not_pinned", `no pin for the ${name} artifact`);
  }
}

async function loadPinned(
  source: ArtifactSource,
  name: ArtifactName,
  expected: string,
): Promise<Uint8Array> {
  const bytes = await source.load(name);
  const computed = await sha256Hex(bytes);
  if (computed !== expected) {
    fail(
      "artifact_mismatch",
      `the ${name} artifact does not match its pin: sha256 is ${computed}, expected ${expected}`,
      { artifact: name, computed, expected },
    );
  }
  return bytes;
}

/**
 * Loads the witness generator and the proving key from `source` and checks each against its pin,
 * failing with artifact_mismatch and both hashes otherwise: what a prover does before it proves.
 */
export async function loadCircuit(
  source: ArtifactSource,
  pins: CircuitPins,
): Promise<CircuitArtifacts> {
  const [wasm, zkey] = await Promise.all([
    loadPinned(source, "wasm", pins.wasm),
    loadPinned(source, "zkey", pins.zkey),
  ]);
  return { wasm, zkey };
}

// The pins of a deployment's circuit, and its verifying key, loaded once after its hash matches the
// pin. A failed load is retried on the next call rather than cached.
export class PinnedArtifacts {
  readonly #source: ArtifactSource;
  readonly #pins: ArtifactPins;
  #verifyingKey: Promise<VerifyingKey> | undefined;

  constructor(source: ArtifactSource, pins: ArtifactPins) {
    checkArtifactPins(pins);
    this.#source = source;
    this.#pins = pins;
  }

  get circuit(): CircuitPins {
    return { wasm: this.#pins.wasm, zkey: this.#pins.zkey };
  }

  verifyingKey(): Promise<VerifyingKey> {
    if (this.#verifyingKey === undefined) {
      const loading = loadPinned(this.#source, "vkey", this.#pins.vkey).then((bytes) =>
        parseVerifyingKey(JSON.parse(new TextDecoder().decode(bytes))),
      );
      this.#verifyingKey = loading;
      loading.catch(() => {
        if (this.#verifyingKey === loading) this.#verifyingKey = undefined;
      });
    }
    return this.#verifyingKey;
  }
}
