# SDK

`@cyphras/private` is the TypeScript SDK for v2 private payments. It derives keys,
builds and proves transactions, keeps a local copy of the pool, and talks to the
services ([services.md](services.md)). It runs in browsers, extension pages and Node.
Its source lives in `sdk/` of this repository.

Proving runs on the user's device. The witness contains `ask` and `nsk`
([notes-and-circuit.md](notes-and-circuit.md)), and spend authority is the knowledge
of those keys, so a remote prover would hold the funds. The SDK has no remote proving
mode.

Identifiers such as F-25 name the finding, from the security review of the cy1
prototype wallet and services, that a requirement fixes.

## API

```ts
import { PrivateWallet, keySource } from "@cyphras/private"
import { snarkjsProver } from "@cyphras/private-prover-snarkjs"

const wallet = await PrivateWallet.open({
  deployment: "mainnet/xlm",
  keys: keySource.mnemonic(words, { account: 0 }),
  prover: snarkjsProver(),
  storage,
  rpcUrl,
})
await wallet.sync()
const address = await wallet.generateAddress()
```

| Call | Does |
| --- | --- |
| `PrivateWallet.open(options)` | Derives the keys, checks the pinned deployment (see Pinned configuration) and loads local state. `options.fetch` MAY route all traffic through a proxy. |
| `generateAddress(index?)` | Returns the `cy1` or `cyt1` address for diversifier index `index`, or the default address when `index` is omitted ([keys-and-addresses.md](keys-and-addresses.md)). |
| `sync()` | Fetches new leaf pages, nullifiers and the entry queue, scans them and updates the local tree. |
| `balance()` | Spendable value, value in pending deposits, and value locked in unconfirmed submissions. |
| `history()` | Shields, refunds, cancellations, received and sent payments, and unshields, including outgoing payments recovered with `ovk` after a restore. |
| `shield({ amount, signer })` | Proves a deposit, has `signer` sign it as the depositor, submits it and returns the deposit ID. |
| `cancelDeposit(id, signer)` | Cancels a deposit that is not yet admitted. `signer` is the depositor. |
| `refundDeposit(id, signer)` | Claims the refund of a flagged deposit. Any account can submit it; the funds go to the depositor. |
| `send({ to, amount, maxFee, relayer? })` | Pays a shielded address through a relayer and returns a submission. |
| `unshield({ to, amount, maxFee, relayer? })` | Pays a Stellar address through a relayer and returns a submission. |
| `unshield({ to, amount, selfRelay })` | The same, submitted and paid for by the `selfRelay` signer with no relayer. |
| `exportViewingKey(kind)` | Encodes the incoming (`"incoming"`) or full (`"full"`) viewing key ([keys-and-addresses.md](keys-and-addresses.md)). |
| `disclosePayment({ txHash, leafIndex })` | Builds a payment disclosure ([encryption.md](encryption.md)). |
| `PrivateWallet.verifyDisclosure(doc)` | Checks a disclosure against the chain. Needs no keys. |
| `PrivateWallet.openViewOnly({ viewingKey })` | A wallet that syncs and reports from a viewing key and cannot spend. |

- Amounts are `bigint` in the asset's smallest unit.
- A signer is `{ publicKey, signTransaction(xdr, networkPassphrase) }`, the shape
  Stellar wallets already expose.
- One operation at a time runs per account; the SDK queues the rest.
- `exportViewingKey` warns that the key reveals the account's whole history and
  future, and points to `disclosePayment` for proving a single payment.

## Key sources

Every source yields the 64-byte seed and the account index that
[keys-and-addresses.md](keys-and-addresses.md) takes as input. The SDK never writes
the seed, or anything derived from it, to storage in plaintext.

| Mode | For | Seed | Account |
| --- | --- | --- | --- |
| (a) mnemonic | wallets | the BIP39 seed of the wallet's mnemonic and passphrase | the SEP-0005 index of the Stellar account |
| (b) signature | dApps that can only ask a Stellar wallet to sign | `SHA-512("cyphras/v2/sig-seed" \|\| signature)` | `0` |
| (c) random | standalone apps | the BIP39 seed of a new 24-word mnemonic | `0` |

### (a) Mnemonic

`keySource.mnemonic(words, { passphrase?, account })`. The same mnemonic gives the same
private account in every wallet that implements this spec, so a user can restore the
private balance in another wallet.

### (b) Signature

`keySource.signature(signer)`, where `signer` has `publicKey` and
`signMessage(message)`. The dApp asks the connected Stellar wallet to sign this
message under SEP-53 with the account's ed25519 key:

```
Cyphras private account v2

Signing this message creates the key to a Cyphras private balance.
Anyone who obtains this signature can spend that balance.
Only sign it in an app you trust.
```

The message is ASCII, with lines separated by a single LF and no trailing newline:
186 bytes, SHA-256
`21aa4daff79f21d43d0e96dfdcc4487df30826ca3d2be1fdcd5e7b3a086f0a54`. Under SEP-53 the
wallet signs `SHA-256("Stellar Signed Message:\n" || message)`.

```
signature = the 64-byte ed25519 signature R || S, decoded from the wallet's base64 or hex
seed      = SHA-512("cyphras/v2/sig-seed" || signature)       64 bytes
```

`"cyphras/v2/sig-seed"` is the 19 ASCII bytes of that string. `vectors/sig-seed.json`
pins the message, a test key, its signature and the resulting seed.

1. The SDK MUST verify the signature against `publicKey` under SEP-53 before using it.
   A wallet that signs the message without the SEP-53 prefix and hash fails here, and
   the mode is unavailable with that wallet.
2. Ed25519 as defined in RFC 8032 is deterministic, but not every signer follows it.
   On first use the SDK requests the signature twice and requires identical bytes. In
   later sessions it refuses to continue if the new seed cannot open the local state
   saved for that public key, because a changed seed would strand the funds sent to
   the addresses of the old one.
3. The signature is a secret. It MUST NOT be logged, stored in plaintext or sent to any
   server. A dApp SHOULD NOT store the seed; if it caches it, it MUST encrypt it under a
   key the user controls.
4. The seed belongs to the signing key, not to the account. Removing that key from the
   account's signers does not change the seed, and losing the key loses the balance.
   Contract accounts and signers that are not ed25519 cannot use this mode.
5. For the same wallet, mode (b) gives a different private account from mode (a). Every
   dApp that uses mode (b) with the same key derives the same private account.

A wallet that holds only an imported secret key can derive a mode (b) seed by signing
the message itself. No dApp is involved, so the phishing risk below does not apply.

**Phishing risk.** Any page that persuades the user to sign this message obtains the
seed and can spend the balance, and the request looks like a harmless "sign to log
in" prompt. Writing the requesting site into the message would not help, because a
phishing page can write any text. The mitigations are:
- the message itself says what signing does;
- the Cyphras wallet recognizes the message and shows a dedicated warning that names
  the requesting origin, and other wallets SHOULD do the same;
- the message has no nonce and MUST NOT be used as a login challenge, so a user never
  has a routine reason to sign it;
- dApps SHOULD keep mode (b) balances small, and MUST tell users that this balance is
  separate from their wallet's own private balance.

### (c) Random

`keySource.random()` generates 256 bits of entropy as a 24-word BIP39 mnemonic and
uses its seed with an empty passphrase. The app MUST show the mnemonic as the backup.
Importing it into a wallet restores the balance as account 0 under mode (a).

### dApp to wallet (future)

A dApp will be able to ask the Cyphras wallet to act for it through the existing
`@cyphras/sdk` connector, as `cyphras.private.*` calls, while the keys stay in the
wallet. The wallet approves every call and authorizes requests by the origin the
browser reports for the sender, never by a field in the message. This mode is not
part of the first release.

## Pinned configuration (F-29)

Each SDK release pins, for every network and vault, values taken from
`deployments/<network>.json`:
- the network passphrase, the vault contract ID, the asset contract ID, `domain` and
  the deploy ledger;
- the vault's wasm hash;
- the SHA-256 of the circuit artifacts: the witness generator, the proving key and the
  verifying key;
- the default indexer and relayer URLs, the relayers' fee addresses, and the fee tier.

When a wallet opens, the SDK reads the vault's executable hash and `domain` with
`getLedgerEntries`, checks the RPC's network passphrase, and checks that every
service's `/v1/health` reports the pinned vault and network. On any mismatch it
refuses to shield or spend. A relayer chosen by the caller must pass the same check.

**Artifacts.** Before proving, the SDK computes the SHA-256 of each artifact and
compares it with the pin. On a mismatch it stops and reports both the computed and the
expected hash. The release script writes the pins from the artifact files; nobody
types or copies a hash by hand.

## Required behaviour

### Root check by ledger entry (F-27)

Before proving, the SDK reads the vault's root history with `getLedgerEntries`, which
takes no source account, and checks that the root of its local tree is in it. It never
simulates a call from the user's account to learn the root. It reads the root history
on every sync, not only before a spend, so that the read is not a sign of an upcoming
spend.

### Bulk sync (F-04, F-05, F-06, F-19, F-21)

- The SDK fetches aligned leaf pages from the last page it completed, and every
  nullifier spent since the last ledger it synced. It tests all of them locally and
  never asks any service about a single note. It MAY follow the indexer's stream and
  sync on each wake event.
- For each new output it checks the view tag first and decrypts only on a match
  ([encryption.md](encryption.md)). It also tries outgoing recovery with `ovk`, so a
  restored wallet finds the payments it sent.
- The tree, notes and plans persist, and are updated incrementally. The SDK never
  rebuilds the tree from leaf 0 to make a spend.
- Notes are keyed by commitment and leaf index, so a repeated commitment is two notes,
  each spendable (F-19).
- The SDK SHOULD compare the indexer's recent leaves and nullifiers with RPC
  `getEvents` for the same ledgers, and treat a difference as an indexer fault.
- With no indexer available, the SDK syncs from RPC events and, on mainnet, from the
  public ledger archive (F-21).

### Submission state machine (F-25)

Each spend is a plan. The SDK saves a write-ahead record of the plan, with its
nullifiers and output commitments, before anything is submitted.

| State | Entered when |
| --- | --- |
| `prepared` | the proof is built and the record saved |
| `submitted` | a relayer or the RPC returned a transaction hash |
| `confirmed` | the transaction with that hash succeeded, or the bulk sync shows the plan's nullifiers spent and its two commitments added by one transaction |
| `superseded` | a nullifier of the plan was spent by a different transaction |
| `dead` | the ledger passed the plan's ExtData `deadline`, or its root left the vault's root history, while its nullifiers are unspent |

- Inputs are marked spent, and outputs added, only in `confirmed`. A spent input counts
  as evidence for a plan only when the spending transaction is the plan's own.
- A proof expires at its ExtData `deadline`, about 120 ledgers after it is built. A
  plan in `prepared` or `submitted` keeps its inputs locked until it is `confirmed`,
  `superseded` or `dead`, so a relayer that sits on a proof delays a payment by at
  most the deadline.
- A retry of a stalled payment MUST spend at least one input of the stalled plan, so
  that at most one of the two can land.
- A full rescan ignores cached spent flags and rebuilds them from the nullifier set.

### Fee cap (F-11)

The SDK refuses a quote above the smallest of the vault's `max_fee`, the caller's
`maxFee`, and the fee the user confirmed. The confirmed fee goes into ExtData before
proving, so a relayer cannot raise it afterwards. If the relayer asks for more at
submission, the SDK asks the user again and proves again.

### Unshield to any address, with nudges (F-26, F-28)

- `to` may be any existing G account, holding a trustline if the asset is not native,
  or a contract address. The SDK checks the destination before proving.
- Muxed (M) addresses are accepted when the vault's `recipient` is a `MuxedAddress`,
  which is decided at the freeze ([vault.md](vault.md)). An exchange deposit that
  needs a muxed ID can then be paid directly. One that needs a text memo still has to
  be paid from an intermediate account, because ExtData carries no memo. If the
  freeze keeps `Address`, the SDK rejects M addresses.
- Before an unshield the SDK warns when:
  - the destination is an account that has shielded from this wallet;
  - the amount equals a recent shield of this wallet, or a whole note from one;
  - less than 24 hours have passed since this wallet's last shield;
  - the destination is a new account, whose funding can link it to its owner;
  - the anonymity set, the number of admitted deposits in the indexer's `/v1/stats`,
    is small.
- An operation that needs several transactions, such as consolidating notes or
  splitting a large unshield, is spread over time with random gaps, never sent in a
  burst.
- The SDK does not offer to unshield the whole balance right after a shield without a
  warning.

### Output order and ExtData (F-08)

Both outputs are built, then their order is chosen uniformly at random
([notes-and-circuit.md](notes-and-circuit.md)). The SDK fills ExtData as follows:

| Kind | `ext_amount` | `fee` | `recipient` | `relayer` |
| --- | --- | --- | --- | --- |
| Shield | `+amount` | `0` | depositor | depositor |
| Transfer | `0` | quoted fee | relayer's fee address | relayer's fee address |
| Unshield, relayed | `-amount` | quoted fee | destination | relayer's fee address |
| Unshield, self-relayed | `-amount` | `0` | destination | the signer's account |

For a transfer, ExtData then names no party to the payment.

### Self-relay for unshields (F-35)

`unshield` accepts a signer instead of a relayer. The signer's account is the
transaction source and the `submitter`, and pays the network fee. The SDK warns that
this account becomes public as the submitter of the unshield and is linked to it.
Self-relay needs no Cyphras service, which makes it the exit when relayers refuse, fail
or are frozen. It is not offered for transfers, which would put the user's account on
a private payment. The SDK also accepts a list of relayers and uses any that reports
the pinned vault and network.

### Deposits

`shield` builds the proof with two dummy inputs and both outputs to the wallet's own
address ([notes-and-circuit.md](notes-and-circuit.md), Transactions), has the
depositor sign, and submits through the RPC. The SDK then follows the deposit in
`/v1/deposits` and reports its earliest admission time, a flag and its reason code,
and the refund or cancellation. A deposit's notes become spendable only once
admitted.

## Storage and network

- **Storage.** The caller supplies a key-value store. The SDK encrypts everything it
  writes with XChaCha20-Poly1305 under `okm("store")[0..32]`, a label of the HKDF
  scheme in [keys-and-addresses.md](keys-and-addresses.md), so local state is per
  network and account and unreadable without the seed.
- **Network.** The SDK sends requests only to the configured RPC, indexer and
  relayers. It has no telemetry and no error reporting service. Through
  `options.fetch` the caller can route private-payment traffic through a proxy, so the
  services see the proxy's address instead of the user's.

## Prover

```ts
export interface Prover {
  prove(witness: TransactionWitness, artifacts: CircuitArtifacts): Promise<Groth16Proof>
}
```

- The SDK checks the artifact hashes before calling the prover, and SHOULD verify every
  proof against the pinned verifying key before submitting it.
- The default prover, `@cyphras/private-prover-snarkjs`, is a separate package that
  wraps snarkjs, which is GPL-3.0.
- Any prover that produces a Groth16 proof for the same proving key can replace it, for
  example a native or WebAssembly prover with a permissive license.

## License

The SDK's own license is an open decision. It MUST be settled before the first npm
release and recorded here.

| Option | Effect |
| --- | --- |
| GPL-3.0 for the SDK and the default prover | Matches snarkjs. Every app that ships the SDK takes on GPL-3.0 for that distribution, so closed-source wallets cannot integrate it. |
| MIT for the SDK core, which is this repository's license, with the default prover as a separate GPL-3.0 package | Apps can use the core under MIT. An app that bundles the snarkjs prover still takes on GPL-3.0 for that bundle, and a permissively licensed prover can later replace it without changing the core. |
| LGPL-3.0 for the SDK core | Allows linking from closed-source apps in principle, but how LGPL applies to bundled and minified JavaScript is unsettled. |

The compiled circuit, the witness generator and the proving key, is built from
circomlib templates under GPL-3.0, and its terms follow the same decision.

## Releases

- Packages are published from signed tags with npm trusted publishing and provenance.
  No long-lived npm token exists.
- Dependencies are pinned to exact versions with a frozen lockfile, and install scripts
  are blocked.
- CI runs the test vectors in `vectors/` for keys, addresses, notes, ExtData encoding,
  encryption and the signature seed.
- Integrators SHOULD pin an exact SDK version and review changes to the pinned
  configuration between versions.
