# Cyphras mainnet ceremony transcript

Public record of the Phase-2 Groth16 ceremony for the `withdraw` proving key. Anyone can
reproduce the checks below to confirm the mainnet verification key is sound.

Status: TEMPLATE - fill in as the ceremony runs. Do not record any entropy here.

## Circuit

- circuit: `withdraw.circom`
- constraints: 12,819 (verify with `snarkjs r1cs info build/withdraw.r1cs`)
- public inputs: 7 (ic length 8); order `[root, nullifierHash, recipient, relayer, relayerFee, amountHash, assetId]`
- snarkjs version: 0.7.6
- `withdraw.r1cs` sha256: `<fill>`

## Phase 1 (powers of tau)

Reused, not generated. Perpetual Powers of Tau (Hermez).

- file: `powersOfTau28_hez_final_14.ptau`
- source: `https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_14.ptau` (mirror; the original Hermez S3 bucket is offline)
- sha256: `<fill>` (cross-checked against an independent published value)
- `snarkjs powersoftau verify` result: `Powers of Tau Ok!`

## Phase 2 contributions

The first zkey is `groth16 setup` of the r1cs over the Hermez ptau.

| # | zkey | contributor | contribution hash (blake2b-512) | output sha256 | attestation |
|---|------|-------------|---------------------------------|---------------|-------------|
| 0 | withdraw_0000.zkey | coordinator (groth16 setup) | n/a | `<fill>` | n/a |
| 1 | withdraw_0001.zkey | `<name>` | `<fill>` | `<fill>` | `<link to signed attestation>` |
| 2 | withdraw_0002.zkey | `<name>` | `<fill>` | `<fill>` | `<link>` |
| 3 | withdraw_0003.zkey | `<name>` | `<fill>` | `<fill>` | `<link>` |

## Beacon (finalization)

A public, unpredictable value pre-announced before it existed.

- source: drand quicknet, round `<fill>` (announced in issue #9 on `<date>`)
- beacon value (round randomness): `<fill>`
- command: `snarkjs zkey beacon withdraw_000N.zkey withdraw_final.zkey "Cyphras mainnet beacon" <beaconHash> 10`
- numIterationsExp: 10

## Final output

- `withdraw_final.zkey` sha256: `<fill>`
- `verification_key.json` sha256: `<fill>`
- `vk_parsed.json` sha256: `<fill>` (used to initialize the mainnet verifier contract)
- `snarkjs zkey verify build/withdraw.r1cs powersOfTau28_hez_final_14.ptau withdraw_final.zkey`: `ZKey Ok!`

## Reproduce these checks

```
npm install
node verify.mjs withdraw.r1cs powersOfTau28_hez_final_14.ptau withdraw_final.zkey
```

Confirm the printed contribution hashes match the table above, and that the final
`verification_key.json` matches the key deployed in the mainnet verifier contract.
