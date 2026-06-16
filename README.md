# cyphras-contracts

Smart contracts and zero-knowledge circuits for Cyphras private payments.

## Layout

```
circuits/      Circom circuits + Groth16 trusted setup (chain-agnostic)
stellar/       Soroban contracts (Rust) - Cargo workspace
  pool/        deposit/withdraw + Merkle tree
  verifier/    on-chain Groth16 proof verification
  factory/     deploys and registers pools per (token, denomination)
deployments/   deployed contract addresses per network
scripts/       build and deploy helpers
```

`circuits/` is kept at the repo root because the ZK circuit is the same across chains.
Chain-specific contracts live under their own directory (`stellar/`), leaving room for
other chains later without touching the circuit.

## Stellar contracts

Requires the Rust toolchain with the `wasm32v1-none` target and the Stellar CLI.

```
cd stellar
cargo test
cargo build --target wasm32v1-none --release
```

## Circuits

See `circuits/README.md`. Requires Node.js and Circom.

## Networks

Deployed addresses are tracked in `deployments/<network>.json` and consumed by the
extension and relayer - never hardcode addresses in clients.

## Compliance posture

v0.2.0 has no on-chain compliance gating. Association-set providers (ASP), allow/deny
lists, and view keys are intentionally deferred: the pool is permissionless and accepts
any valid deposit and reveal. These layers can be added later without changing the pool,
verifier, or proof system, and the decision is revisited before serving mainnet value.
