# Cyphras mainnet ceremony transcript

Public record of the Phase-2 Groth16 ceremony for the `withdraw` proving key. Anyone can
reproduce the checks below to confirm the mainnet verification key is sound.

Status: FINAL - ceremony complete 2026-06-23. No entropy is recorded here.

## Circuit

- circuit: `withdraw.circom`
- constraints: 12,819 (verify with `snarkjs r1cs info build/withdraw.r1cs`)
- public inputs: 7 (ic length 8); order `[root, nullifierHash, recipient, relayer, relayerFee, amountHash, assetId]`
- circom version: 2.2.3
- snarkjs version: 0.7.6
- `withdraw.r1cs` sha256: `faab07f23773915ed2fda6b1f8bcd7be400d28fb61ec24c51899403ca9ac0aff`

## Phase 1 (powers of tau)

Reused, not generated. Perpetual Powers of Tau (Hermez).

- file: `powersOfTau28_hez_final_14.ptau`
- source: `https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_14.ptau` (mirror; the original Hermez S3 bucket is offline)
- sha256: `489be9e5ac65d524f7b1685baac8a183c6e77924fdb73d2b8105e335f277895d` (cross-checked against an independent published value)
- `snarkjs powersoftau verify` result: `Powers of Tau Ok!`

## Phase 2 contributions

The first zkey is `groth16 setup` of the r1cs over the Hermez ptau.

| # | zkey | contributor | contribution hash (blake2b-512) | output sha256 | attestation |
|---|------|-------------|---------------------------------|---------------|-------------|
| 0 | withdraw_0000.zkey | coordinator (groth16 setup) | n/a | `d35aa163f034510771c1610b19720f7a8daf1417003b4e78aa4b8bdcf06ea2fe` | n/a |
| 1 | withdraw_0001.zkey | Indra Mahesa (github: zinct) | `44ab3c309ebf4322a9b59fb9e405ba8ffc1cef62f47e8eb052eccd216897339392bb23628a61a1b649bd84df800b344ecc1b72454532d5b81c6994e7bc66a4f6` | `03e523c6a40e3f92945747b79e83045081ad7b145b2f2ef708a6d30f5ac8c210` | https://github.com/cyphras/cyphras-extension/issues/9#issuecomment-4737760929 |
| 2 | withdraw_0002.zkey | Kenny Rivaldi (github: kennyrivaldi) | `f50a3c609740749fb03ac6e32d7d4814b81325977fb9777ab01b370b5315ca6d5cf2424dd2ceb5e2736659ecbb3053cd76163f4b60a4824b66ac8184000324d4` | `af9d9c369d05c061d45bba27e2f75701a4829efafd51b4bd0493cee9a9dacf15` | https://github.com/cyphras/cyphras-extension/issues/9#issuecomment-4740452844 |
| 3 | withdraw_0003.zkey | Pebriansyah (github: cryptoeights) | `e5e9e5813a70233f957054393c5ccaaf869c96dea54f276168b0128675c5b0aebb408a4b7aa0ce21b96dde1bcffcf97dbf673d67f73c99100acd388cf66fe78a` | `ee62dc45438407e56f6cccff7929aec0fe52ca15f173ba9ff9644a995baff615` | https://github.com/cyphras/cyphras-extension/issues/9#issuecomment-4742722458 |
| 4 | withdraw_0004.zkey | Wildan Syukri Niam (github: wildanniam) | `0623af56e0bedf6fbc3005e3fe7c49e4fd6cd4768f7bcd76f8505c46e9abf9369a1908a38a995aaa819a568fa057bf1b0d48a08e05bacbf91e4f887c94362343` | `36ab6b3080fdb59a8be480f9745f87cf82e1ac6456f58e5cd0a029252d3e7c76` | https://github.com/cyphras/cyphras-extension/issues/9#issuecomment-4742960026 |
| 5 | withdraw_0005.zkey | Raph (github: rawritude) | `3c76d062f48d335ab619e64cd7c8a9ac2ffdb47989caf553043da5e3f7c7f47ffaee9acae1aa7e7267fcdbb3d554641454a6291830b7151c042152e65266f73a` | `e30b1de67107bfde463720df66962f4731e35891f232df342c9e49c69e2b726c` | https://github.com/cyphras/cyphras-extension/issues/9#issuecomment-4773314482 |

## Beacon (finalization)

A public, unpredictable value pre-announced before it existed.

- source: drand quicknet, round `29809999` (announced in issue #9 on 2026-06-23, before the round existed)
- beacon value (round randomness): `7c76e660f7677c56030d645db330b164f0c3c5f28bf9c68ee58cd1e6dd2f917d`
- command: `snarkjs zkey beacon withdraw_0005.zkey withdraw_final.zkey "Cyphras mainnet beacon" 7c76e660f7677c56030d645db330b164f0c3c5f28bf9c68ee58cd1e6dd2f917d 10`
- numIterationsExp: 10

## Final output

- `withdraw_final.zkey` sha256: `904ba52cae6485ecf0f95cadd14c6690ec3494a157ffd8febd7ab82c99c9d853`
- `verification_key.json` sha256: `6a9739e220a694368b88ece1091e0b6830ac2447eb7370d485491820932d3a76`
- `vk_parsed.json` sha256: `5da51c49a584670b9dd83073931e06966fbe0c16758d6a3b6165a5c98869082b` (used to initialize the mainnet verifier contract)
- `snarkjs zkey verify build/withdraw.r1cs powersOfTau28_hez_final_14.ptau withdraw_final.zkey`: `ZKey Ok!`

## Reproduce these checks

```
npm install
node verify.mjs withdraw.r1cs powersOfTau28_hez_final_14.ptau withdraw_final.zkey
```

Confirm the printed contribution hashes match the table above, and that the final
`verification_key.json` matches the key deployed in the mainnet verifier contract.
