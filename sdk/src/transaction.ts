import { L, type Point, isPrimeOrderPoint } from "./babyjub.ts";
import { bytesToBigIntBE, randomBytes } from "./bytes.ts";
import { encryptOutput } from "./encryption.ts";
import { fail } from "./errors.ts";
import { type ExtData, checkExtData, extDataHash, publicAmount } from "./extdata.ts";
import { P } from "./field.ts";
import type { AddressKey, SpendingKeys } from "./keys.ts";
import { LEVELS, ZEROS, rootFromPath } from "./merkle.ts";
import { MAX_VALUE, noteCommitment, nullifier } from "./notes.ts";
import type { TransactionWitness } from "./prover.ts";

// The randomness a transaction draws. Tests replace it to make transactions reproducible.
export interface TransactionRandomness {
  fieldElement(): bigint;
  scalar(): bigint;
  position(): number;
  coin(): boolean;
}

const uniform = (bytes: number, modulus: bigint): bigint =>
  bytesToBigIntBE(randomBytes(bytes)) % modulus;

export const systemRandomness: TransactionRandomness = {
  fieldElement: () => uniform(64, P),
  scalar: () => {
    for (;;) {
      const s = uniform(64, L);
      if (s !== 0n) return s;
    }
  },
  position: () => Number(uniform(4, 1n << 32n)),
  coin: () => ((randomBytes(1)[0] as number) & 1) === 1,
};

export interface SpendNote {
  readonly value: bigint;
  readonly gd: Point;
  readonly q: Point;
  readonly pkd: Point;
  readonly rcm: bigint;
  readonly pos: number;
  readonly path: readonly bigint[];
}

export interface OutputRequest {
  readonly address: AddressKey;
  readonly value: bigint;
}

export interface BuiltOutput {
  readonly address: AddressKey;
  readonly value: bigint;
  readonly rcm: bigint;
  readonly cm: bigint;
  readonly esk: bigint;
  readonly ciphertext: Uint8Array;
}

export interface BuiltTransaction {
  readonly witness: TransactionWitness;
  readonly ext: ExtData;
  readonly nullifiers: readonly [bigint, bigint];
  readonly commitments: readonly [bigint, bigint];
  // The outputs in the order the transaction carries them.
  readonly outputs: readonly [BuiltOutput, BuiltOutput];
  // The input slots that spend real notes; the others hold dummies.
  readonly realSlots: readonly number[];
}

export type ExtTerms = Omit<ExtData, "encryptedOutput0" | "encryptedOutput1">;

export interface TransactionRequest {
  readonly keys: SpendingKeys;
  // The wallet's own address, which dummy inputs use.
  readonly self: AddressKey;
  readonly root: bigint;
  readonly domain: bigint;
  readonly inputs: readonly SpendNote[];
  readonly outputs: readonly [OutputRequest, OutputRequest];
  readonly ext: ExtTerms;
  readonly random?: TransactionRandomness;
}

const MAX_POSITION = 2 ** LEVELS;

function checkValue(value: bigint): void {
  if (value < 0n || value > MAX_VALUE) fail("invalid_argument", "a note value is a 64-bit amount");
}

// Builds the witness and ExtData of a 2-in/2-out transaction. Missing inputs are padded with
// dummies at the wallet's own address, and the order of the inputs and of the outputs is chosen
// uniformly at random.
export function buildTransaction(request: TransactionRequest): BuiltTransaction {
  const random = request.random ?? systemRandomness;
  const { keys, self, root, domain } = request;
  if (request.inputs.length > 2) fail("invalid_argument", "a transaction spends at most two notes");

  for (const input of request.inputs) {
    checkValue(input.value);
    if (input.value === 0n) fail("invalid_argument", "a spent note has a nonzero value");
    if (!Number.isInteger(input.pos) || input.pos < 0 || input.pos >= MAX_POSITION) {
      fail("invalid_argument", "a leaf position is a 32-bit index");
    }
    if (input.path.length !== LEVELS) fail("invalid_argument", "a Merkle path has 32 siblings");
    const cm = noteCommitment(input);
    // A wrong path would only fail inside the prover; finding it here costs 32 hashes.
    if (rootFromPath(cm, input.pos, input.path) !== root) {
      fail("tree_unverified", "a note's path does not lead to the transaction's root");
    }
  }
  const realCount = request.inputs.length;
  const dummies: SpendNote[] = Array.from({ length: 2 - realCount }, () => ({
    value: 0n,
    gd: self.gd,
    q: self.q,
    pkd: self.pkd,
    rcm: random.fieldElement(),
    pos: random.position(),
    path: ZEROS.slice(0, LEVELS),
  }));
  let slots = [...request.inputs, ...dummies];
  let realSlots = request.inputs.map((_, i) => i);
  if (random.coin()) {
    slots = slots.reverse();
    realSlots = realSlots.map((i) => 1 - i);
  }
  const [in0, in1] = slots as [SpendNote, SpendNote];
  const nf0 = nullifier(noteCommitment(in0), in0.pos, keys.nkFold);
  const nf1 = nullifier(noteCommitment(in1), in1.pos, keys.nkFold);
  if (nf0 === nf1) fail("invalid_argument", "both inputs spend the same note");

  for (const output of request.outputs) {
    checkValue(output.value);
    if (!isPrimeOrderPoint(output.address.gd) || !isPrimeOrderPoint(output.address.pkd)) {
      fail("invalid_address", "an output address is not a prime-order point", { rule: "subgroup" });
    }
  }
  const totalIn = request.inputs.reduce((sum, input) => sum + input.value, 0n);
  const totalOut = request.outputs.reduce((sum, output) => sum + output.value, 0n);
  if (totalIn + request.ext.extAmount - request.ext.fee !== totalOut) {
    fail("invalid_argument", "inputs, external amount and fee do not balance the outputs");
  }

  let built = request.outputs.map(({ address, value }): BuiltOutput => {
    const rcm = random.fieldElement();
    const esk = random.scalar();
    const note = { d: address.d, gd: address.gd, pkd: address.pkd, value, rcm };
    return {
      address,
      value,
      rcm,
      esk,
      cm: noteCommitment(note),
      ciphertext: encryptOutput(note, keys.ovk, esk),
    };
  });
  if (random.coin()) built = built.reverse();
  const [out0, out1] = built as [BuiltOutput, BuiltOutput];
  if (out0.cm === out1.cm) fail("invalid_argument", "both outputs have the same commitment");

  const ext: ExtData = {
    ...request.ext,
    encryptedOutput0: out0.ciphertext,
    encryptedOutput1: out1.ciphertext,
  };
  checkExtData(ext);
  const witness: TransactionWitness = {
    root,
    publicAmount: publicAmount(ext.extAmount, ext.fee),
    extDataHash: extDataHash(ext),
    domain,
    nf: [nf0, nf1],
    cmOut: [out0.cm, out1.cm],
    inValue: [in0.value, in1.value],
    inAsk: [keys.ask, keys.ask],
    inNsk: [keys.nsk, keys.nsk],
    inGd: [in0.gd, in1.gd],
    inQ: [in0.q, in1.q],
    inRcm: [in0.rcm, in1.rcm],
    inPos: [BigInt(in0.pos), BigInt(in1.pos)],
    inPathElements: [in0.path, in1.path],
    outValue: [out0.value, out1.value],
    outGd: [out0.address.gd, out1.address.gd],
    outPkd: [out0.address.pkd, out1.address.pkd],
    outRcm: [out0.rcm, out1.rcm],
  };
  return {
    witness,
    ext,
    nullifiers: [nf0, nf1],
    commitments: [out0.cm, out1.cm],
    outputs: [out0, out1],
    realSlots,
  };
}
