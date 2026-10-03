import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex } from "./bytes.ts";
import { fail } from "./errors.ts";
import { type VerifyingKey, parseVerifyingKey } from "./groth16.ts";
import type { CircuitArtifacts } from "./prover.ts";

/** The circuit artifacts: the witness generator, the proving key and the verifying key. */
export type ArtifactName = "wasm" | "zkey" | "vkey";

/**
 * Where the SDK reads the circuit artifacts from, for example files shipped with an extension or
 * fetched from the release. The SDK checks every file against its pinned SHA-256 before use.
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

// Loads the artifacts once, after their hashes match the pins. A failed load is retried on the
// next call rather than cached.
export class PinnedArtifacts {
  readonly #source: ArtifactSource;
  readonly #pins: ArtifactPins;
  #proving: Promise<CircuitArtifacts> | undefined;
  #verifyingKey: Promise<VerifyingKey> | undefined;

  constructor(source: ArtifactSource, pins: ArtifactPins) {
    checkArtifactPins(pins);
    this.#source = source;
    this.#pins = pins;
  }

  async #load(name: ArtifactName): Promise<Uint8Array> {
    const bytes = await this.#source.load(name);
    const computed = await sha256Hex(bytes);
    const expected = this.#pins[name];
    if (computed !== expected) {
      fail(
        "artifact_mismatch",
        `the ${name} artifact does not match its pin: sha256 is ${computed}, expected ${expected}`,
        { artifact: name, computed, expected },
      );
    }
    return bytes;
  }

  proving(): Promise<CircuitArtifacts> {
    if (this.#proving === undefined) {
      const loading = Promise.all([this.#load("wasm"), this.#load("zkey")]).then(
        ([wasm, zkey]) => ({ wasm, zkey }),
      );
      this.#proving = loading;
      loading.catch(() => {
        if (this.#proving === loading) this.#proving = undefined;
      });
    }
    return this.#proving;
  }

  verifyingKey(): Promise<VerifyingKey> {
    if (this.#verifyingKey === undefined) {
      const loading = this.#load("vkey").then((bytes) =>
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
