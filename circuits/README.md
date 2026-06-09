# circuits

Circom circuits and Groth16 trusted setup for Cyphras private payments.

## Layout

```
src/
  withdraw.circom        main circuit
  lib/
    merkle.circom        Merkle proof verification (DualMux + Poseidon)
scripts/
  parse-vk.mjs           verification_key.json -> vk_parsed.json (contract format)
test/
  withdraw.test.mjs      proof generation + verification (positive and negative)
build/                   generated artifacts (gitignored)
```

## Circuit: withdraw

Proves ownership of a committed note and its membership in the pool Merkle tree
without revealing which note or the spender.

Constraints:
1. `nullifierHash == Poseidon(nullifier, secret)`
2. `amountHash == Poseidon(amount, relayerFee, amountBlinding)`
3. `commitment = Poseidon(nullifier, secret, amountHash, assetId)`
4. `commitment` is in the Merkle tree with `root` (20 levels)
5. `amount` and `relayerFee` are range-checked to 64 bits so a near-modulus field
   element cannot be reinterpreted as a different integer on-chain
6. `recipient` and `relayer` are squared to keep them in the constraint system; without
   this the optimizer would drop these otherwise-unused public inputs and they would no
   longer be bound to the proof (tamper-evidence)

Size: ~12,390 constraints (5,857 non-linear + 6,533 linear), 7 public inputs, 44 private.

### Public input order (hard contract)

```
[root, nullifierHash, recipient, relayer, relayerFee, amountHash, assetId]
```

This order is shared with the verifier contract (cyphras-contracts/stellar/verifier)
and the client (cyphras-extension). Reordering breaks proof verification.

`relayerFee` is public so the pool can enforce that the XLM fee it pays the relayer
equals the fee the user committed. Without this a relayer could overdraw the pool's
shared XLM balance. The proof MUST be generated client-side by the note owner; the
relayer only submits it and cannot alter recipient/relayer/relayerFee without
invalidating the proof.

## Build

Requires the Rust `circom` binary (not the deprecated npm `circom`) and Node.js.

```
npm install
npm run build
```

`npm run build` runs: compile, powers of tau (phase 1), groth16 setup, a single
contributor phase 2, export the verification key, and parse it for the contract.

Powers of tau is generated locally for testnet. The pipeline also runs
`snarkjs powersoftau verify` and `snarkjs zkey verify` so the proving key is provably
tied to this r1cs and ptau.

WARNING: the testnet setup uses a single contributor with hardcoded entropy in
package.json. This is reproducible by anyone, which means the toxic waste is public and
the resulting zkey can forge proofs for arbitrary withdrawals. It is fine for testnet
(no real funds) and MUST NEVER back a pool holding value. Mainnet requires a multi-party
ceremony with a final beacon and no recorded entropy (Issue #9). A reproducible setup is
by definition a fully-known, forgeable setup.

## Artifacts

Committed: `verification_key.json`, `vk_parsed.json` (used to init the verifier
contract), and `vectors.json` (Poseidon test vectors for Issue #3). All public and
auditable.

Gitignored (regenerated, large): `withdraw.wasm`, `withdraw_final.zkey`, `*.ptau`.
The extension bundles `withdraw.wasm` and `withdraw_final.zkey` (Issue #5).

## Critical compatibility note

The circuit uses circomlib Poseidon. The on-chain pool computes its Merkle tree with
the Stellar Protocol 25 Poseidon host function. These MUST produce identical hashes for
the same inputs, or on-chain roots will never match circuit roots and no proof will ever
verify. The verifier/pool work (Issue #3) must assert this with shared test vectors
before deployment.

Likewise the G2 coordinate ordering in `vk_parsed.json` must match what
`bn254_multi_pairing_check` expects (see note in `scripts/parse-vk.mjs`).

## Test

```
npm test
```
