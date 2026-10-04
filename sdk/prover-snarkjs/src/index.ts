/// <reference path="./snarkjs.d.ts" />
// The default prover of @cyphras/private, in a package of its own because snarkjs is GPL-3.0: the
// core depends on no snarkjs code, and an app that wants another prover never ships it.
import {
  type ArtifactSource,
  type CircuitArtifacts,
  type CircuitPins,
  CyphrasError,
  type Groth16Proof,
  type Prover,
  type TransactionWitness,
  circuitInputs,
  loadCircuit,
} from "@cyphras/private";

/** Options of the snarkjs prover. */
export interface SnarkjsProverOptions {
  /**
   * Where the prover reads the witness generator and the proving key. It checks both against the
   * pins of each proof it is asked for before proving with them, and keeps them for later proofs.
   */
  readonly artifacts: ArtifactSource;
  /**
   * Proves on the calling thread. Chrome MV3 extension pages need it: their content security
   * policy blocks the blob: workers snarkjs starts otherwise.
   */
  readonly singleThread?: boolean;
}

/** A Prover backed by snarkjs, with a way to stop the worker threads it starts. */
export interface SnarkjsProver extends Prover {
  close(): Promise<void>;
}

function decimal(value: unknown): bigint {
  if (typeof value !== "string" || !/^[0-9]+$/.test(value)) {
    throw new TypeError("snarkjs returned a malformed proof");
  }
  return BigInt(value);
}

function affine(point: readonly unknown[] | undefined): readonly [bigint, bigint] {
  if (point === undefined || point.length !== 3 || point[2] !== "1") {
    throw new TypeError("snarkjs returned a proof point that is not affine");
  }
  return [decimal(point[0]), decimal(point[1])];
}

/** The default prover: snarkjs Groth16 over the pinned witness generator and proving key. */
export function snarkjsProver(options: SnarkjsProverOptions): SnarkjsProver {
  // Checked circuits by their pins; a failed load is tried again for the next proof.
  const circuits = new Map<string, Promise<CircuitArtifacts>>();
  const circuit = (pins: CircuitPins): Promise<CircuitArtifacts> => {
    const key = `${pins.wasm}/${pins.zkey}`;
    let loading = circuits.get(key);
    if (loading === undefined) {
      loading = loadCircuit(options.artifacts, pins);
      circuits.set(key, loading);
      loading.catch(() => circuits.delete(key));
    }
    return loading;
  };
  return {
    async prove(witness: TransactionWitness, pins: CircuitPins): Promise<Groth16Proof> {
      const artifacts = await circuit(pins);
      const { groth16 } = await import("snarkjs");
      let result: Awaited<ReturnType<typeof groth16.fullProve>>;
      try {
        result = await groth16.fullProve(
          circuitInputs(witness),
          artifacts.wasm,
          artifacts.zkey,
          undefined,
          undefined,
          { singleThread: options.singleThread ?? false },
        );
      } catch {
        // The underlying error can name witness signals; it is not passed on.
        throw new CyphrasError("prover_failed", "the witness generator or the prover failed");
      }
      const { pi_a, pi_b, pi_c } = result.proof;
      const [bx, by, bz] = pi_b;
      if (bz?.[0] !== "1" || bz[1] !== "0" || bx?.length !== 2 || by?.length !== 2) {
        throw new TypeError("snarkjs returned a proof point that is not affine");
      }
      return {
        a: affine(pi_a),
        b: [
          [decimal(bx[0]), decimal(bx[1])],
          [decimal(by[0]), decimal(by[1])],
        ],
        c: affine(pi_c),
        publicSignals: result.publicSignals.map(decimal),
      };
    },

    async close(): Promise<void> {
      const curve = (globalThis as { curve_bn128?: { terminate(): Promise<void> } }).curve_bn128;
      await curve?.terminate();
    },
  };
}
