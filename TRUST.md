# Trust model and admin powers

What the on-chain components can and cannot do, who holds the keys, and how a compromise is handled.
This is the trust anchor for Cyphras: the relayer is untrusted (it can only censor, never move or
misdirect funds), so the contracts and their admin key are the parts that must be held correctly.

## Factory admin

A single Admin address gates the factory's privileged entry points (all `admin.require_auth()`):

- `create_pool(token, denomination)` - deploy a new pool for a denomination.
- `rotate_pool(token, denomination)` - deploy a fresh pool for a denomination (the old one keeps its
  funds and stays withdrawable; new deposits go to the new pool).
- `propose_pool_wasm` / `set_pool_wasm` - change the WASM used for FUTURE pool deployments. Gated by a
  ~24h timelock (`WASM_TIMELOCK_LEDGERS = 17_280` at ~5s ledgers): propose, wait, then enact.
- `set_admin(new_admin)` - hand the admin role to another address.

What the admin CANNOT do:

- It cannot move or freeze funds in any pool. Withdrawals are authorized only by a valid ZK proof.
- It cannot change the verifier or the WASM of an already-deployed pool. Pools and the verifier are
  immutable after deploy; `set_pool_wasm` affects only pools created afterward.
- It cannot forge a proof or bypass the nullifier check.

So the worst a stolen admin key can do is deploy rogue NEW pools or rotate denominations - a
censorship/confusion vector, not a theft of existing deposits. Existing depositors can always
self-reclaim from the pool they deposited into.

## Verifier verification key (VK)

The Groth16 VK is set once in the verifier's `__constructor` and is **immutable** thereafter
(`stellar/verifier/src/lib.rs`). There is no upgrade or setter. This is deliberate: an upgradable VK
would let a key holder swap in a VK that accepts forged proofs and drain pools.

Consequence: the only remedy for a bad or compromised VK is to **redeploy** the verifier and stand up
a new factory + pools, then migrate. Because pools bind their verifier at creation, an existing pool
cannot be pointed at a new verifier.

The VK lives in instance storage and is kept alive by the relayer's TTL keeper.

## Trusted setup (testnet vs mainnet)

The testnet VK in `circuits/build/testnet/vk_parsed.json` comes from a development trusted setup whose toxic
waste is known. **It is forgeable and testnet-only.** Anyone with the setup output can mint proofs
that pass verification, so testnet pools must never hold real value.

Mainnet requires a Phase-2 multi-party MPC ceremony so no single party knows the toxic waste
(tracked in cyphras-extension Issue #9). The mainnet verifier must be deployed with the ceremony VK,
never `vk_parsed.json`. The deploy path enforces this (see the deploy script's VK gate).

## Key custody

- **Testnet:** the factory admin is a single key. Acceptable because testnet holds no real value.
- **Mainnet (required before launch):** move the factory admin to a Stellar multisig (M-of-N
  signers) via `set_admin`, so no single key can deploy rogue pools or hand off the admin role.
  Document the signer set, the threshold, and where each signer key is held before mainnet deploy.
  Keep signer keys on separate hardware/custody; the ~24h `set_pool_wasm` timelock gives time to
  react to an unexpected proposal.

## Compromise response

See [cyphras-relayer/docs/runbooks.md](https://github.com/cyphras/cyphras-relayer/blob/main/docs/runbooks.md)
for the operational playbook (admin-key compromise -> `set_admin` to a safe key/multisig; verifier or
zkey compromise -> redeploy + migrate).
