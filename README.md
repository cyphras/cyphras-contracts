# cyphras-contracts

Smart contracts and zero-knowledge circuits for Cyphras private payments.

## Layout

```
circuits/      Circom circuits + Groth16 trusted setup (chain-agnostic)
```

`circuits/` is kept at the repo root because the ZK circuit is the same across chains.

## Circuits

Requires Node.js and circom 2.2.3. From `circuits/`: `npm ci`, `npm run compile` (fails unless
the r1cs is the frozen one), `npm run ptau`, `npm test` and `npm run check:o2`.
`npm run setup:testnet-forgeable` makes dev-only testnet keys: whoever runs it can forge proofs.

## Networks

Deployed addresses are tracked in `deployments/<network>.json` and consumed by the
extension and relayer - never hardcode addresses in clients.
