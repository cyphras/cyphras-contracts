# cyphras-contracts

Smart contracts and zero-knowledge circuits for Cyphras private payments.

## Layout

```
circuits/      Circom circuits + Groth16 trusted setup (chain-agnostic)
contracts/     Soroban contracts (Rust) - Cargo workspace
  vault/       shielded pool: entry queue, Merkle tree, nullifiers, limits, guardian
  verifier/    Groth16 verifier with the verifying key compiled in
  poseidon2/   Poseidon2 over BN254 on the CAP-0075 host function
  types/       proof and ExtData types that clients encode
```

`circuits/` is kept at the repo root because the ZK circuit is the same across chains.

## Contracts

Requires the Rust toolchain with the `wasm32v1-none` target.

```
cd contracts
cargo test
cargo build --target wasm32v1-none --release
```

The default build embeds the forgeable testnet verifying key. `--features mainnet` embeds
the ceremony key pinned in `contracts/verifier/build/check.rs` and fails until one is
pinned. The vault's proof fixtures come from `npm run fixtures:contracts` in `circuits/`,
after `npm run setup:testnet-forgeable`.

## Circuits

Requires Node.js and circom 2.2.3. From `circuits/`: `npm ci`, `npm run compile` (fails unless
the r1cs is the frozen one), `npm run ptau`, `npm test` and `npm run check:o2`.
`npm run setup:testnet-forgeable` makes dev-only testnet keys: whoever runs it can forge proofs.

## Networks

Deployed addresses are tracked in `deployments/<network>.json` and consumed by the
extension and relayer - never hardcode addresses in clients.
