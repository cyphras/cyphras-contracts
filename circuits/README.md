# circuits

Circom circuits and Groth16 trusted setup for Cyphras private payments.

## Layout

```
src/
  withdraw.circom        main circuit
  lib/
    merkle.circom        Merkle proof verification
    poseidon.circom      Poseidon hash wrappers
test/                    circuit tests
```

## Build

Requires Node.js and Circom. Build artifacts (`*.r1cs`, `*.zkey`, `*.ptau`, `*_js/`)
are gitignored - they are regenerated, and the proving key is too large to commit.

The verification key (`verification_key.json`, `vk_parsed.json`) IS committed once
generated, so the on-chain verifier and any auditor can check it.

## Trusted setup

Testnet uses a single-contributor setup. Mainnet requires a multi-party (MPC) ceremony
before any real funds enter a pool.
