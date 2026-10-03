pragma circom 2.2.3;

// Domain tags: 0x01 note commitment, 0x02 nullifier, 0x05 pkd, 0x06 nk, 0x07 ak, 0x08 gd,
// 0x09 address, 0x10 ivk. 0x11 is reserved; 0x12 (DiversifyHash) is used outside the circuit.

include "circomlib/circuits/babyjub.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";
include "poseidon2/poseidon2_hash.circom";
include "keys.circom";
include "merkleProof.circom";
include "note.circom";

template SpendNote(levels) {
  signal input root;
  signal input value;
  signal input ask;
  signal input nsk;
  signal input gd[2];
  signal input q[2];
  signal input rcm;
  signal input pos;
  signal input pathElements[levels];
  signal output nf;

  component askCanonical = AssertLtL();
  askCanonical.s <== ask;
  component nskCanonical = AssertLtL();
  nskCanonical.s <== nsk;

  component ak = BabyPbk();
  ak.in <== ask;
  component nk = BabyPbk();
  nk.in <== nsk;
  component akFold = FoldPoint(0x07);
  akFold.p <== [ak.Ax, ak.Ay];
  component nkFold = FoldPoint(0x06);
  nkFold.p <== [nk.Ax, nk.Ay];

  component ivkHash = Poseidon2(2);
  ivkHash.inputs <== [akFold.out, nkFold.out];
  ivkHash.domainSeparation <== 0x10;
  component ivk = ReduceModL();
  ivk.in <== ivkHash.out;

  // With a low-order gd, pkd = ivk * gd would hold for many ivk, each giving the note another
  // nullifier.
  component gdPrimeOrder = AssertPrimeOrder();
  gdPrimeOrder.p <== gd;
  gdPrimeOrder.q <== q;

  component pkd = ScalarMulAny();
  pkd.s <== ivk.out;
  pkd.p <== gd;

  // Reproducing a commitment that is in the tree is the proof of ownership.
  component cm = NoteCommitment();
  cm.value <== value;
  cm.gd <== gd;
  cm.pkd <== pkd.out;
  cm.rcm <== rcm;

  // MerkleProof decomposes pos into exactly `levels` path bits, so the nullifier below and the
  // path name the same leaf.
  component path = MerkleProof(levels);
  path.leaf <== cm.out;
  path.index <== pos;
  path.pathElements <== pathElements;

  component nfHash = Poseidon2(3);
  nfHash.inputs <== [cm.out, pos, nkFold.out];
  nfHash.domainSeparation <== 0x02;
  nf <== nfHash.out;

  // A zero-value input is a dummy: it skips the root check but still spends its nullifier.
  component rootCheck = ForceEqualIfEnabled();
  rootCheck.enabled <== value;
  rootCheck.in <== [root, path.root];

  component valueRange = Num2Bits(64);
  valueRange.in <== value;
}

template OutputNote() {
  signal input value;
  signal input gd[2];
  signal input pkd[2];
  signal input rcm;
  signal output cm;

  // Subgroup membership is left to the sender's address parser: a bad point only strands the
  // sender's own note, because SpendNote refuses it.
  component gdOnCurve = BabyCheck();
  gdOnCurve.x <== gd[0];
  gdOnCurve.y <== gd[1];
  component pkdOnCurve = BabyCheck();
  pkdOnCurve.x <== pkd[0];
  pkdOnCurve.y <== pkd[1];

  component commitment = NoteCommitment();
  commitment.value <== value;
  commitment.gd <== gd;
  commitment.pkd <== pkd;
  commitment.rcm <== rcm;
  cm <== commitment.out;

  component valueRange = Num2Bits(64);
  valueRange.in <== value;
}

template Transaction(levels, nIns, nOuts) {
  // Public inputs first: their declaration order is the verifier's input order.
  signal input root;
  signal input publicAmount;
  signal input extDataHash;
  signal input domain;
  signal input nf[nIns];
  signal input cmOut[nOuts];

  signal input inValue[nIns];
  signal input inAsk[nIns];
  signal input inNsk[nIns];
  signal input inGd[nIns][2];
  signal input inQ[nIns][2];
  signal input inRcm[nIns];
  signal input inPos[nIns];
  signal input inPathElements[nIns][levels];

  signal input outValue[nOuts];
  signal input outGd[nOuts][2];
  signal input outPkd[nOuts][2];
  signal input outRcm[nOuts];

  component spend[nIns];
  var sumIns = 0;
  for (var i = 0; i < nIns; i++) {
    spend[i] = SpendNote(levels);
    spend[i].root <== root;
    spend[i].value <== inValue[i];
    spend[i].ask <== inAsk[i];
    spend[i].nsk <== inNsk[i];
    spend[i].gd <== inGd[i];
    spend[i].q <== inQ[i];
    spend[i].rcm <== inRcm[i];
    spend[i].pos <== inPos[i];
    spend[i].pathElements <== inPathElements[i];
    spend[i].nf === nf[i];
    sumIns += inValue[i];
  }

  component create[nOuts];
  var sumOuts = 0;
  for (var j = 0; j < nOuts; j++) {
    create[j] = OutputNote();
    create[j].value <== outValue[j];
    create[j].gd <== outGd[j];
    create[j].pkd <== outPkd[j];
    create[j].rcm <== outRcm[j];
    create[j].cm === cmOut[j];
    sumOuts += outValue[j];
  }

  // Equal nullifiers would let one note fund two inputs.
  component nfDistinct[nIns * (nIns - 1) / 2];
  var pair = 0;
  for (var i = 0; i < nIns - 1; i++) {
    for (var j = i + 1; j < nIns; j++) {
      nfDistinct[pair] = AssertNonZero();
      nfDistinct[pair].in <== nf[i] - nf[j];
      pair++;
    }
  }

  // With 64-bit values both sums stay far below p, so publicAmount, read as a signed integer,
  // is exactly sumOuts - sumIns.
  sumIns + publicAmount === sumOuts;

  // A public input that appears in no constraint could be changed without invalidating the proof.
  signal extDataHashSquare <== extDataHash * extDataHash;
  signal domainSquare <== domain * domain;
}

component main {public [root, publicAmount, extDataHash, domain, nf, cmOut]} = Transaction(20, 2, 2);
