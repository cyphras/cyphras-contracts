# Cyphras private payments v2: specification

Status: draft for the circuit freeze. Normative words (MUST, SHOULD, MAY) follow RFC 2119.

Private payments v2 is a shielded UTXO pool on Stellar (Soroban): 2-in/2-out join-split
notes, Groth16 proofs over BN254, Poseidon2 hashing through the CAP-0075 host
function, and Sapling-style keys with diversified `cy1` addresses. It replaces the v1
fixed-denomination pools (tag `v1-mainnet-final`) and the cy1 testnet prototype.

## Documents

| File | Covers |
| --- | --- |
| [keys-and-addresses.md](keys-and-addresses.md) | Seed derivation per network, key hierarchy, diversified addresses, address and viewing-key encodings |
| [notes-and-circuit.md](notes-and-circuit.md) | Notes, commitments, nullifiers, the Merkle tree, and the circuit statement |
| [encryption.md](encryption.md) | Output ciphertexts, view tags, outgoing recovery, payment disclosure |
| [vault.md](vault.md) | The vault contract: entry gate, limits, governance, storage, events, invariants |
| [services.md](services.md) | Indexer, relayer, keeper, screening service and watcher |
| [sdk.md](sdk.md) | The TypeScript SDK and its key sources |
| [threat-model.md](threat-model.md) | Adversaries, trust model, leakage model, known limits |
| [ceremony.md](ceremony.md) | The phase-2 trusted setup |
| [screening-policy.md](screening-policy.md) | What the deposit screening checks and how decisions are recorded |

## What changes from the cy1 prototype

| Area | cy1 prototype | v2 |
| --- | --- | --- |
| Key derivation | `sha256(seed, tag)` with one tag set for every network | HKDF-SHA512 with the network and account in the info string |
| Address prefix | `cy1` on every network | `cy1` on mainnet, `cyt1` on testnet |
| Diversified addresses | `g_d = H(d) * Base8`, linkable by anyone | `g_d = DiversifyHash(d)`, a hash to the curve with no known discrete log |
| Note commitment | binds `pk_d` | binds `g_d` and `pk_d` |
| Amount range | 248 bits | 64 bits |
| Ciphertext | 147 bytes, no outgoing recovery | 181 bytes with a view tag and an outgoing ciphertext |
| ExtData | recipient, relayer, fee, amount, ciphertexts | adds the vault contract ID, the network ID and a deadline; the recipient may be a muxed address |
| Deposits | enter the tree at once | wait in a screened entry queue, then are admitted or refunded |
| Governance | one admin, instant wasm upgrade | no upgrade path; a guardian that can pause, and halt for a bounded time |
| Limits | deposit cap and TVL cap | adds per-depositor daily cap, daily outflow cap that can only rise and always lets the full pool exit within 7 days, relayer fee cap |
| Root history | 64 roots | 256 roots |
| Identity registries | `register_commitment`, `register_enc_key` | removed |

## Network parameters

| Network | Address HRP | Passphrase |
| --- | --- | --- |
| mainnet | `cy` | `Public Global Stellar Network ; September 2015` |
| testnet | `cyt` | `Test SDF Network ; September 2015` |

A key, address or proof made for one network MUST NOT be accepted on the other.
