# Threat model

What each party can and cannot do to funds and privacy under v2, which components are
trusted for what, what each observer learns, and where the design stops. Mechanisms
are specified in [vault.md](vault.md), [notes-and-circuit.md](notes-and-circuit.md),
[encryption.md](encryption.md), [services.md](services.md) and [sdk.md](sdk.md).

## Assumptions

- Groth16 over BN254 is sound when at least one setup contributor was honest
  ([ceremony.md](ceremony.md)). Poseidon2 is collision resistant. DDH holds on Baby
  Jubjub. SHA-2, HKDF and XChaCha20-Poly1305 are secure.
- Stellar consensus is honest. Validators may still freeze ledger keys by a CAP-77
  vote.
- The user's device and the wallet or SDK build it runs are not compromised.

## Adversaries

### Chain observer

Anyone who reads the ledger.
- **Can** see each deposit's depositor, amount and time, its screening outcome and
  reason code, and the leaf positions its notes took; each unshield's recipient,
  amount, fee and relayer, and the submitting account of a self-relayed one; the time,
  fee and relayer of each transfer; and every nullifier, commitment and ciphertext. Can
  match public deposits to public unshields by amount and timing.
- **Cannot** tell which leaf a nullifier spends, who sends or receives a transfer, or
  any amount inside the pool. Cannot link two diversified addresses of one wallet, read
  a ciphertext, or learn anything from a view tag.

### Relayer

- **Can** see the client's IP address unless the client uses a proxy, the time of each
  request, and the proof and ExtData before inclusion: for an unshield, the
  destination and amount. Can refuse, delay or censor. Can hold a proof and submit it
  later, for as long as its root stays in the 256-root history. Can link submissions
  that come from one address.
- **Cannot** change the recipient, amount, fee or outputs, which `extDataHash` binds.
  Cannot take more than the fee in the proof, which the vault caps at `max_fee`.
  Cannot learn which notes a proof spends, or stop an exit: the user can self-relay an
  unshield or pick another relayer.

### Indexer

- **Can** see the client's IP address, when it syncs, how far it has synced and when it
  is online. Can withhold or delay data, and serve a forged leaf set or nullifier set.
- **Cannot** learn which notes, addresses or nullifiers belong to a client, because no
  request names one. Cannot make a client prove against a forged tree, because the
  client checks its root against the chain. Cannot create a spendable note, because a
  decrypted note must match its on-chain commitment. A forged nullifier set can hide or
  overstate a balance until the client cross-checks with RPC events or another
  indexer.

### RPC provider

- **Can** see the client's IP address, the transactions the client submits through it
  (shields and self-relayed unshields) and the entries it reads (the root history,
  an unshield destination). Can answer with stale or false data, or refuse a
  submission. A provider that also carries the user's public-account traffic from the
  same address can correlate the two by address and time.
- **Cannot** link a root read to the user's public account through the request
  itself, because the read takes no source account. Cannot move funds. False data
  makes a proof fail on chain; it cannot make the vault accept one.

### ASP (screening operator)

- **Can** delay every deposit by not attesting; refuse a deposit by flagging it, which
  sends it back to its depositor; let a dirty deposit in; and see every destination
  submitted to its relayer, including refused ones.
- **Cannot** take, hold or redirect funds, since refunds go only to the depositor.
  Cannot block or slow an exit, act on an admitted note, or see inside the pool.

### Stolen guardian key

An attacker who reaches the signing threshold of the guardian account.
- **Can**:
  - pause deposits and transfers for as long as it holds the key;
  - halt the vault for up to 72 hours, and again only after the 7-day cooldown;
  - tighten every limit except `max_daily_outflow` at once;
  - queue loosenings, which apply after 7 days and which the watcher reports;
  - cancel the owner's queued changes.

  It cannot throttle exits shut. `max_daily_outflow` never decreases, and the vault
  keeps `7 * max_daily_outflow >= tvl_cap`, so the whole pool can still leave within
  a week outside a halt. Setting `max_fee` to zero stops fee-paying relayers, but not
  self-relayed unshields.
- **Cannot** move funds, change the verifier, edit the tree, the nullifier set or
  pending deposits, single out a user, or stop a cancel or a refund.

### Stolen ASP key

- **Can** attest pending deposits early, though each still waits out its delay; flag
  pending deposits, which sends them back to their depositors; and unflag deposits so
  that flagged ones are admitted. It keeps these powers until the key is rotated.
- **Cannot** move funds, touch admitted notes, or affect exits.
- **Response:** the guardian halts the vault, which stops admission. The owner rotates
  the `asp` account's signers with its offline keys, screens every pending deposit
  again and flags the bad ones, then resumes. An attestation cannot be withdrawn, so
  the remedy is a flag on each deposit that should not enter.

### Validators using CAP-77

- **Can** freeze any ledger key by a consensus vote: the vault's instance, code or
  storage, the asset contract, the relayer, keeper, `asp` or guardian accounts, or a
  user's account. A frozen vault stops completely, exits included, and nothing Cyphras
  or a user can do gets around that. The freeze list is public on the ledger, and a
  vote can let specific reviewed transactions through.
- **Cannot** freeze one user's notes, because the nullifier entries a note will touch
  are unknown without that user's `nk`. They can freeze the entry of a known pending
  deposit. They cannot move funds.
- Cyphras would ask validators for a freeze only for a proof forgery that is draining
  the vault and that a halt cannot contain. It would name the vault's instance and code
  keys, and publish the request.

### Malicious web page or extension

- **A web page can** phish a mode (b) signature, which yields the seed of that private
  account ([sdk.md](sdk.md)); imitate a Cyphras site; and ask the wallet to sign. It
  **cannot** read keys held by the Cyphras wallet, or act with another site's
  permissions, because the wallet takes the requesting origin from the browser, never
  from the page's message.
- **An extension** with access to a dApp's pages can read keys that live in those pages
  (modes (b) and (c) in a web app), rewrite displayed addresses and read the clipboard.
  It **cannot** read another extension's storage.

Keys held in a web page are only as safe as that page and every extension that can
read it.

### Malicious counterparty

- **A recipient can** learn the amount, time and leaf of the payment, and that the
  other output of that transaction belongs to the sender. It can prove the payment to
  anyone, since it holds the note. It can send dust or malformed outputs, which the
  wallet ignores after the commitment check, at the cost of a transaction each.
- **A recipient cannot** learn the sender's address, balance, other notes or later
  activity, the value of the sender's other output, or spend or freeze any of the
  sender's notes.
- **A sender cannot** learn when, or whether, the recipient spends the note: that needs
  the recipient's `nk`.

### Circuit or setup bug

- **Soundness.** A soundness bug, or a setup whose every contributor colluded or
  leaked their randomness, lets an attacker forge proofs and drain the vault. The loss
  is bounded by `tvl_cap`, slowed by `max_daily_outflow`, paused by a guardian halt of
  up to 72 hours, and partly covered by a restitution reserve of 5 percent of the TVL
  cap. The verifying key cannot be replaced: the fix is a new vault and a new
  ceremony. After a halt ends, the forger and honest users compete for the same daily
  outflow.
- **Completeness.** A bug that makes some valid notes unprovable leaves those notes
  locked, because the vault has no upgrade path.
- **Zero knowledge.** A prover that misuses its randomness can leak witness data,
  including keys.
- **Mitigations:** one multi-party ceremony with an external contributor and a public
  beacon ([ceremony.md](ceremony.md)); CI checks on the verifying key; a tamper suite,
  circomspect and differential tests against a reference implementation; external
  audits before limits are raised.

### Compromised publishing pipeline

The Chrome Web Store listing of the wallet, the npm packages, the repository and its
CI, the service images, and the ceremony release.
- **Can** ship code that steals seeds, which loses every affected user's public and
  private funds; point a release's pinned configuration at a malicious contract; and
  make services refuse or lie, which affects liveness only.
- **Cannot** change a deployed vault or its verifying key, or forge proofs with a
  swapped proving key, since proofs from a wrong key fail against the vault's key.
- **Mitigations:** verified CRX uploads with an offline key and staged publishing; npm
  trusted publishing with provenance; signed tags; reproducible builds with recorded
  digests; hardware security keys on every publishing account; no telemetry in the
  wallet; integrators pin exact versions and review changes to pinned configuration.

## Trust

| Component | Trusted for | If it misbehaves or fails |
| --- | --- | --- |
| Circuit, ceremony and vault code | the safety of all funds | forged proofs drain the vault up to its limits; see Circuit or setup bug |
| Stellar validators | everything | a CAP-77 freeze stops the vault, exits included |
| Asset issuer | the vault's balance of that asset | the issuer of a revocable asset may be able to freeze the vault's balance; Circle's USDC issuer has `AUTH_REVOCABLE` set |
| Guardian | liveness of deposits and transfers; not fund safety | pauses, halts of up to 72 hours, tightened limits |
| ASP | admission of deposits | deposits delayed or refunded; dirty deposits admitted |
| Relayer | liveness of relayed spends; metadata | censorship, fixed by self-relay or another relayer; network metadata if it keeps logs |
| Indexer | liveness of sync; metadata | false data, caught by the root check and cross-checks; sync timing if it keeps logs |
| Keeper | liveness of admission and TTL | delays; anyone can make the same calls |
| RPC provider | liveness and reads | false reads, caught by cross-checks; network metadata |
| Watcher | detection | late alerts |
| Wallet, SDK and their release pipeline | everything the user holds | theft of seeds |

The services' no-log policy cannot be verified from outside. A user who needs network
privacy should treat the relayer, the indexer and the RPC provider as observers and
reach them through a proxy.

If Cyphras stops operating, no new deposit is admitted, because nobody attests; every
pending deposit can still be cancelled by its depositor. Admitted notes stay
spendable: wallets sync from RPC events and the public ledger archive, and unshield by
self-relay. Archived vault entries are restored automatically when a transaction
touches them, at the submitter's cost.

## Who sees what

| Observer | Learns | Does not learn |
| --- | --- | --- |
| Chain observer | deposits: depositor, amount, time, screening outcome, leaf positions; unshields: recipient, amount, fee, relayer, time, and the submitter of a self-relayed one; transfers: time, fee, relayer; all nullifiers, commitments and ciphertexts | which leaf a nullifier spends; in-pool senders, recipients and amounts; links between diversified addresses |
| Relayer | client IP and request times; for an unshield, destination and amount before inclusion; which submissions share an IP | notes, keys, which notes a proof spends |
| Indexer | client IP; sync progress and online times | which notes, addresses or nullifiers are the client's |
| RPC provider | client IP; shields and self-relayed unshields sent through it; entries read | notes; the account behind a root read, unless the same IP reveals it |
| Screening operator | everything public about deposits; destinations submitted to its relayer, including refused ones | in-pool activity |
| Sender of a payment | the recipient's address, the note and its leaf | whether and when the recipient spends it |
| Recipient of a payment | amount, time and leaf; that the other output belongs to the sender | the sender's address, balance or other notes |
| Holder of an incoming viewing key | every incoming note of the account, at all its addresses, with value and time | spends and outgoing notes; cannot spend |
| Holder of a full viewing key | incoming notes, spends and outgoing notes: the whole history and future | cannot spend |
| Verifier of a payment disclosure | one note: value, address, transaction and leaf; with `esk`, that the discloser built it | anything else |

## Known limits

1. **Dirty funds found after admission stay in the pool.** Screening happens at entry.
   Once a deposit is admitted, its notes look like every other note, and nobody,
   Cyphras included, can trace or block them inside the pool.
2. **The anonymity set is small at launch.** An unshield hides among the deposits
   admitted before it, and with small limits and few users that set is small. Cyphras
   publishes the number of admitted deposits and distinct depositors so that users can
   judge it.
3. **Amount and timing correlation.** Deposits and unshields move public amounts at
   public times. Matching amounts, short gaps and bursts link them. The entry delay and
   the SDK's warnings reduce this; they do not remove it.
4. **Deposits are public.** The depositor's account, the amount and the time are on
   chain, and the screening record ties a decision to them.
5. **A single operator with no external signers.** Cyphras holds every guardian key,
   on separate devices in separate places, which guards against one stolen device but
   not against Cyphras. Cyphras also holds the `asp` key and runs the default relayer,
   indexer, keeper and watcher. Only the immutable vault and verifying key, and the
   ceremony with its external contributor, do not depend on Cyphras. There is no way
   to replace the verifying key; a path for that waits for external signers and a
   later vault.
6. **No upgrade.** A fix ships as a new vault that users move to themselves, which
   splits the anonymity set.
7. **Per-depositor limits are per address.** Spreading deposits over many addresses
   defeats them. `tvl_cap` and `max_daily_outflow` are the hard bounds.
8. **Network metadata.** Without a proxy, the relayer, the indexer and the RPC provider
   see the client's IP address.
9. **Viewing keys cannot be revoked.** A shared viewing key keeps working for the life
   of the account.
10. **Event history.** Leaves exist only in events, and RPC keeps events for about a
    week. Mainnet history can be rebuilt from the public ledger archive; testnet history
    only from backups.
