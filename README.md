# cyphras-contracts

Smart contracts and zero-knowledge circuits for Cyphras private payments.

## Layout

```
circuits/      Circom circuits + Groth16 trusted setup (chain-agnostic)
contracts/     Soroban contracts (Rust) - Cargo workspace
  vault/       shielded pool: entry and exit queues, Merkle tree, nullifiers, limits, guardian
  verifier/    Groth16 verifier with the verifying key compiled in
  poseidon2/   Poseidon2 over BN254 on the CAP-0075 host function
  types/       proof and ExtData types that clients encode
sdk/           TypeScript SDK - npm workspace
  private/          @cyphras/private: keys, addresses, sync and spends
  prover-snarkjs/   @cyphras/private-prover-snarkjs: the default prover
  examples/         a private transfer on testnet, runnable
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

## SDK

`@cyphras/private` is the TypeScript SDK for the shielded pool: keys and `cy1` addresses,
a sync that checks the tree against the vault's roots, and deposits, private transfers and
withdrawals. Proofs are made on the user's device, so no service sees a key or a witness.
`@cyphras/private-prover-snarkjs` is the default prover.

Testnet only for now. The mainnet entry of `PINNED_DEPLOYMENTS` stays empty until the
trusted-setup ceremony, and opening a wallet on mainnet fails until then.

```
npm install @cyphras/private @cyphras/private-prover-snarkjs @stellar/stellar-base
```

Requires Node.js 22.18 or later, or a browser; `@stellar/stellar-base` 15 is a peer
dependency. Below, `words` is a mnemonic, `artifacts` loads the circuit files
`transaction.wasm`, `transaction.zkey` and `verification_key.json`, which the SDK checks
against the hashes the deployment pins, and `signer` is the Stellar account that pays a
deposit in. The testnet files are attached to the [`testnet-artifacts-v2`][artifacts]
release; a browser app bundles or serves its own copy.

[artifacts]: https://github.com/cyphras/cyphras-contracts/releases/tag/testnet-artifacts-v2

```ts
import { MemoryStore, PrivateWallet, keySource } from "@cyphras/private";
import { snarkjsProver } from "@cyphras/private-prover-snarkjs";

const XLM = 10_000_000n;
const wallet = await PrivateWallet.open({
  deployment: "testnet/xlm",
  keys: keySource.mnemonic(words, { account: 0 }),
  prover: snarkjsProver({ artifacts }),
  artifacts,
  storage: new MemoryStore(),
  rpcUrl: "https://soroban-testnet.stellar.org",
  singleInstance: true,
});
console.log(wallet.generateAddress()); // cyt1...
await wallet.shield({ amount: 10n * XLM, signer });
await wallet.sync(); // the deposit counts once the vault admits it
console.log(await wallet.balance());
await wallet.send({ to: "cyt1...", amount: 3n * XLM, maxFee: XLM });
await wallet.unshield({ to: "G...", amount: 2n * XLM, maxFee: XLM });
```

- `@cyphras/private` is licensed under Apache-2.0.
- `@cyphras/private-prover-snarkjs` is licensed under GPL-3.0-only, as snarkjs is under the
  GPL-3.0; an app that bundles it distributes that bundle under the GPL-3.0. Any other
  implementation of the SDK's `Prover` interface can take its place.

[`sdk/examples/private-transfer.ts`][sample] runs a private transfer on testnet end to end.

[sample]: https://github.com/cyphras/cyphras-contracts/blob/HEAD/sdk/examples/private-transfer.ts

## Protocol

**Notes.** Value in the pool is held in notes. A note is an amount, the recipient's
address key and a random value; the vault adds its Poseidon2 commitment to a Merkle tree
of depth 32 and publishes the note encrypted to the recipient. A `cy1` address (`cyt1` on
testnet) names one diversified key of a wallet, and two addresses of one wallet cannot be
linked. A wallet finds its notes by trying each new one with its viewing key. Each vault
holds one asset.

**Transactions.** A transaction spends two notes and creates two, with a Groth16 proof
over BN254 that the spent notes are in the tree under one of the vault's last 256 roots,
that the spender holds their keys, and that value is conserved: what the spent notes hold,
plus a deposit, equals what the new notes hold, plus a withdrawal and the relayer's fee.
The proof commits to the vault, the network, a deadline, the amounts, the recipient, the
relayer and the ciphertexts, so a relayer can submit it but cannot change it.

**Nullifiers.** Spending a note publishes its nullifier, a hash of the note's commitment,
its position in the tree and the owner's nullifier key. The vault refuses a nullifier it
has seen, so each note is spent once, and nobody without the key can tell which note a
nullifier belongs to.

**Entry gate.** A deposit does not enter the tree at once. It waits in the vault's entry
queue while a screening service checks the depositor and the accounts that funded it, and
then for the vault's entry delay, about 10 minutes on testnet. A cleared deposit is
attested and admitted, and its commitments join the tree. A refused deposit is flagged on
chain with a public reason code and goes back in full to the account it came from, and to
no other. Screening fails closed, and the depositor can cancel at any time before
admission.

**Exit queue.** A withdrawal is paid at once while the day's outflow window has room;
otherwise it waits in a first-in, first-out exit queue that anyone can release as windows
open, within a bound on its wait. A payout the asset contract refuses is set aside and can
be claimed back into the queue, so it never blocks the exits behind it. The vault has no
upgrade function; its guardian can pause or halt it for a bounded time, but cannot move,
reorder or edit exits.

## Networks

Deployed addresses are tracked in `deployments/<network>.json` and consumed by the
extension and relayer - never hardcode addresses in clients.
