# scripts

Build and deploy helpers for circuits and Soroban contracts.

## deploy-testnet.mjs

Builds the contracts and deploys the verifier, pool wasm, factory, and one pool
per token and denomination, then writes the addresses to
`deployments/testnet.json`.

Prerequisites:

- Stellar CLI installed, with an identity to sign and pay for the deploy.
- That identity funded on testnet: `stellar keys fund <identity> --network testnet`.
- The wasm target: `rustup target add wasm32v1-none`.
- The trusted-setup output present at `circuits/build/vk_parsed.json` (run the
  circuit build first if it is missing).

Run, passing the signing identity inline:

```
DEPLOY_IDENTITY=<identity> node scripts/deploy-testnet.mjs
```

It prints the new `FACTORY_ID` and `INDEXER_START_LEDGER` for the relayer at the
end. Override the RPC with `STELLAR_RPC_URL` if needed.

Planned:

- circuit build + trusted setup
- mainnet deploy
