import type { PinnedArtifacts } from "./artifacts.ts";
import { CyphrasError, fail } from "./errors.ts";
import { type TxProof, toHostProof } from "./extdata.ts";
import { verifyGroth16 } from "./groth16.ts";
import { type Prover, type TransactionWitness, publicInputs } from "./prover.ts";

// Proves a transaction with the pinned circuit and accepts the proof only if it carries the
// expected public inputs and verifies against the pinned verifying key, so a faulty prover can
// cost a retry but never a transaction the vault refuses.
export async function proveTransaction(
  witness: TransactionWitness,
  prover: Prover,
  artifacts: PinnedArtifacts,
): Promise<TxProof> {
  const vk = await artifacts.verifyingKey();
  let proof;
  try {
    proof = await prover.prove(witness, artifacts.circuit);
  } catch (err) {
    if (err instanceof CyphrasError) throw err;
    fail("prover_failed", "the prover failed");
  }
  const expected = publicInputs(witness);
  const signals = proof.publicSignals;
  if (signals.length !== expected.length || signals.some((s, i) => s !== expected[i])) {
    fail("proof_invalid", "the prover returned different public inputs");
  }
  if (!verifyGroth16(vk, proof, expected)) {
    fail("proof_invalid", "the proof does not verify against the pinned verifying key");
  }
  return {
    proof: toHostProof(proof),
    root: witness.root,
    publicAmount: witness.publicAmount,
    extDataHash: witness.extDataHash,
    inputNullifiers: witness.nf,
    outputCommitments: witness.cmOut,
  };
}
