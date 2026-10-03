pragma circom 2.2.3;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/switcher.circom";
include "poseidon2/poseidon2_compress.circom";

// Recomputes the root from the leaf at `index`. Num2Bits(levels) gives every index exactly one
// path, so the index the caller binds elsewhere is the leaf proven here.
template MerkleProof(levels) {
  signal input leaf;
  signal input index;
  signal input pathElements[levels];
  signal output root;

  component indexBits = Num2Bits(levels);
  indexBits.in <== index;

  component order[levels];
  component hash[levels];
  signal node[levels + 1];
  node[0] <== leaf;
  for (var i = 0; i < levels; i++) {
    // bit i set: the running node is the right child at level i
    order[i] = Switcher();
    order[i].sel <== indexBits.out[i];
    order[i].L <== node[i];
    order[i].R <== pathElements[i];

    hash[i] = PoseidonCompress();
    hash[i].inputs[0] <== order[i].outL;
    hash[i].inputs[1] <== order[i].outR;
    node[i + 1] <== hash[i].out;
  }
  root <== node[levels];
}
