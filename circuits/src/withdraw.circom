pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/bitify.circom";
include "lib/merkle.circom";

// Proves ownership of a committed note and its membership in the pool's Merkle
// tree, without revealing which note or the spender's identity.
//
// SECURITY: the proof MUST be generated client-side by the note owner. recipient,
// relayer, and relayerFee are public inputs the prover chooses; the relayer only
// submits the finished proof and cannot alter them without invalidating it.
//
// Public input order is a hard contract shared with the verifier contract and the
// client. Do not reorder:
//   [root, nullifierHash, recipient, relayer, relayerFee, amountHash, assetId]
//
// relayerFee is public so the pool can enforce that the XLM fee it pays the relayer
// equals the fee the user committed - without this a relayer could overdraw the
// pool's shared XLM balance.
template Withdraw(levels) {
    signal input secret;
    signal input nullifier;
    signal input amount;
    signal input amountBlinding;
    signal input pathElements[levels];
    signal input pathIndices[levels];

    signal input root;
    signal input nullifierHash;
    signal input recipient;
    signal input relayer;
    signal input relayerFee;
    signal input amountHash;
    signal input assetId;

    // Range-check the numeric note values so a near-modulus field element cannot be
    // reinterpreted as a different integer by the on-chain contract.
    component amountBits = Num2Bits(64);
    amountBits.in <== amount;

    component relayerFeeBits = Num2Bits(64);
    relayerFeeBits.in <== relayerFee;

    component nh = Poseidon(2);
    nh.inputs[0] <== nullifier;
    nh.inputs[1] <== secret;
    nh.out === nullifierHash;

    component ah = Poseidon(3);
    ah.inputs[0] <== amount;
    ah.inputs[1] <== relayerFee;
    ah.inputs[2] <== amountBlinding;
    ah.out === amountHash;

    component cm = Poseidon(4);
    cm.inputs[0] <== nullifier;
    cm.inputs[1] <== secret;
    cm.inputs[2] <== ah.out;
    cm.inputs[3] <== assetId;

    component tree = MerkleProof(levels);
    tree.leaf <== cm.out;
    tree.root <== root;
    for (var i = 0; i < levels; i++) {
        tree.pathElements[i] <== pathElements[i];
        tree.pathIndices[i] <== pathIndices[i];
    }

    // recipient and relayer take no arithmetic role, so without a constraint the
    // optimizer would drop them and they would no longer be bound to the proof.
    // Squaring forces a real constraint, keeping them tamper-evident. The other
    // public inputs are already constrained above. (relayerFee, amountHash, and
    // assetId feed the hashes, so they need no extra guard.)
    signal recipientSquared;
    recipientSquared <== recipient * recipient;

    signal relayerSquared;
    relayerSquared <== relayer * relayer;
}

component main {
    public [root, nullifierHash, recipient, relayer, relayerFee, amountHash, assetId]
} = Withdraw(20);
