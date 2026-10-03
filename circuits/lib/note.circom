pragma circom 2.2.3;

include "poseidon2/poseidon2_hash.circom";

template FoldPoint(tag) {
  signal input p[2];
  signal output out;
  component h = Poseidon2(2);
  h.inputs <== p;
  h.domainSeparation <== tag;
  out <== h.out;
}

// gd is a free witness when the note is spent, so it must be bound here: otherwise anyone could
// spend with gd = (1 / ivk') * pkd for their own ivk'.
template NoteCommitment() {
  signal input value;
  signal input gd[2];
  signal input pkd[2];
  signal input rcm;
  signal output out;

  component gdFold = FoldPoint(0x08);
  gdFold.p <== gd;
  component pkdFold = FoldPoint(0x05);
  pkdFold.p <== pkd;

  component addrFold = Poseidon2(2);
  addrFold.inputs[0] <== gdFold.out;
  addrFold.inputs[1] <== pkdFold.out;
  addrFold.domainSeparation <== 0x09;

  component cm = Poseidon2(3);
  cm.inputs[0] <== value;
  cm.inputs[1] <== addrFold.out;
  cm.inputs[2] <== rcm;
  cm.domainSeparation <== 0x01;
  out <== cm.out;
}
