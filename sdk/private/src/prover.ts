import type { Point } from "./babyjub.ts";
import type { AffineProof } from "./extdata.ts";

type Pair<T> = readonly [T, T];

/**
 * Every signal of `Transaction(32, 2, 2)`: the eight public inputs and the private witness. It
 * holds the spend keys ask and nsk, so it never leaves the device.
 */
export interface TransactionWitness {
  readonly root: bigint;
  readonly publicAmount: bigint;
  readonly extDataHash: bigint;
  readonly domain: bigint;
  readonly nf: Pair<bigint>;
  readonly cmOut: Pair<bigint>;
  readonly inValue: Pair<bigint>;
  readonly inAsk: Pair<bigint>;
  readonly inNsk: Pair<bigint>;
  readonly inGd: Pair<Point>;
  readonly inQ: Pair<Point>;
  readonly inRcm: Pair<bigint>;
  readonly inPos: Pair<bigint>;
  readonly inPathElements: Pair<readonly bigint[]>;
  readonly outValue: Pair<bigint>;
  readonly outGd: Pair<Point>;
  readonly outPkd: Pair<Point>;
  readonly outRcm: Pair<bigint>;
}

/** The circuit's witness generator (wasm) and proving key (zkey), already checked against their pins. */
export interface CircuitArtifacts {
  readonly wasm: Uint8Array;
  readonly zkey: Uint8Array;
}

/** The pinned SHA-256 of the circuit's witness generator and proving key, as lowercase hex. */
export interface CircuitPins {
  readonly wasm: string;
  readonly zkey: string;
}

/**
 * A Groth16 proof over BN254 in affine coordinates, with every Fq2 coordinate as [c0, c1], and
 * the public signals the prover computed.
 */
export interface Groth16Proof extends AffineProof {
  readonly publicSignals: readonly bigint[];
}

/**
 * Proves a transaction on the user's device. Any implementation that produces a Groth16 proof
 * for the pinned proving key fits. It loads the witness generator and the proving key itself and
 * proves only with files that match `circuit`, as loadCircuit checks them; the SDK verifies the
 * proof against the pinned verifying key after the call.
 */
export interface Prover {
  prove(witness: TransactionWitness, circuit: CircuitPins): Promise<Groth16Proof>;
}

// The public inputs in the circuit's order, which is the verifier's.
export function publicInputs(w: TransactionWitness): bigint[] {
  return [w.root, w.publicAmount, w.extDataHash, w.domain, ...w.nf, ...w.cmOut];
}

const dec = (x: bigint): string => x.toString();
const point = (p: Point): string[] => [dec(p[0]), dec(p[1])];

/** The witness as named circuit inputs with decimal values, the form circom witness generators take. */
export function circuitInputs(w: TransactionWitness): Record<string, unknown> {
  return {
    root: dec(w.root),
    publicAmount: dec(w.publicAmount),
    extDataHash: dec(w.extDataHash),
    domain: dec(w.domain),
    nf: w.nf.map(dec),
    cmOut: w.cmOut.map(dec),
    inValue: w.inValue.map(dec),
    inAsk: w.inAsk.map(dec),
    inNsk: w.inNsk.map(dec),
    inGd: w.inGd.map(point),
    inQ: w.inQ.map(point),
    inRcm: w.inRcm.map(dec),
    inPos: w.inPos.map(dec),
    inPathElements: w.inPathElements.map((path) => path.map(dec)),
    outValue: w.outValue.map(dec),
    outGd: w.outGd.map(point),
    outPkd: w.outPkd.map(point),
    outRcm: w.outRcm.map(dec),
  };
}
