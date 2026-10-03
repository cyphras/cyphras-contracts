# Off-chain services

Five services support the vaults. None of them can move funds, alter a proof or spend
a note: every movement of funds needs a proof that the vault verifies
([vault.md](vault.md)). The services affect liveness and metadata privacy, and each
has a fallback that does not depend on Cyphras.

| Service | Instances | Public API | Signs transactions | When it fails |
| --- | --- | --- | --- | --- |
| Indexer | one per vault | yes | no | wallets sync from RPC events and the public ledger archive |
| Relayer | one per vault | yes | channel accounts | another relayer, or a self-relayed unshield |
| Keeper | one per vault | no | keeper account | anyone can call `bump_ttl`, `admit` and `refund` |
| Screening service | one per network | partly | the vault's `asp` account | deposits wait in the queue; depositors can cancel |
| Watcher | one or more per network | no | no | anyone can run its public code |

Identifiers such as F-18 name the finding, from the security review of the cy1
prototype services and wallet, that a requirement fixes.

## Rules for every service

### Privacy

1. **No IP or request logs (F-36).** No service, proxy or container runtime records
   client addresses, request paths or parameters, user agents or request times.
   Rate-limit state lives in memory only. The logging policy below is published.
2. **No per-note queries (F-04).** No endpoint takes a commitment, nullifier, leaf
   index or note as input. Clients download whole sets or fixed pages and test
   membership locally. The one exception is a transaction status, asked of the
   relayer that submitted the transaction and therefore already knows it.
3. **No user secrets.** Services never receive seeds, spend keys, viewing keys, note
   lists or wallet identifiers.
4. **Secrets per service (F-16).** Each service has its own keys, database
   credentials and secret files, readable by that service only.
5. **Small hot floats.** A key held by a running service controls at most a few days
   of network fees. Fee income and reserves sit in accounts whose keys are offline.
6. **Generic errors (F-15, F-22).** Responses carry a fixed error code, never an
   internal or RPC error message.
7. **No third parties on the request path.** No analytics, CDN or tracking code sees
   client requests.

### Submitting transactions

The relayer, the keeper and the screening service submit transactions. Each of them:
- keeps one transaction in flight per source account, holds the sequence number under
  a lock, and reloads it from the chain after `txBAD_SEQ` (F-14);
- sets the inclusion fee from the p90 of `getFeeStats`, never the network minimum
  (F-14);
- handles `sendTransaction` statuses as follows: PENDING and DUPLICATE mean poll
  `getTransaction`; TRY_AGAIN_LATER is not success, and the same signed envelope is
  resubmitted with backoff until its time bound passes; ERROR is a failure (F-14);
- reports success only after `getTransaction` returns SUCCESS (F-14, F-24);
- retries failures with exponential backoff capped at a few minutes, and alerts after
  repeated failure (F-24).

### Identity

Every health endpoint reports the network ID (SHA-256 of the network passphrase) and
the vault contract IDs it serves, so that a client can refuse a service that points
elsewhere (F-29).

## Indexer

### Responsibilities

- Rebuild the vault's state from every vault event since the deploy ledger recorded
  in the deployment file. A live-state snapshot is never a starting point, because it
  omits archived entries.
- Reconcile its root and leaf count with the contract every ledger, and stop serving
  on mismatch.
- Serve leaves, the nullifier set and the entry queue in bulk.
- Track every deposit through attestation, flagging, admission, cancellation and
  refund.
- Keep backups, and be able to rebuild from public data alone (F-21).

### Ingest

- Events come from `getEvents`, filtered to the vault contract, in ledger windows.
  Pagination follows the cursor inside each window; a full page is never an error
  (F-20).
- Decoding dispatches on the event topic before it reads the data (F-23). The vault is
  immutable, so its topic set is fixed: an unknown topic or a malformed known event is
  an ingest fault, which stops serving and alerts.
- The events of each transaction must have the shape the vault emits
  ([vault.md](vault.md), Events). For example, a `transact` emits two `new_nullifier`
  and two `new_commitment` events, and an `admit` emits two `new_commitment` events
  and one `deposit_admitted` event per deposit.
- Leaves are keyed by leaf index. Commitments carry no uniqueness constraint, and a
  repeated commitment is stored as a separate leaf (F-18). Leaf indices MUST be
  contiguous; a gap stops serving.
- A nullifier seen twice breaks a vault invariant: the indexer stops serving and
  raises a critical alert.
- The indexer computes the root with the Poseidon2 compression of
  [notes-and-circuit.md](notes-and-circuit.md), checked against the pinned vectors.

### Reconciliation

After applying the events up to ledger L, the indexer reads the vault's next leaf
index and root history with `getLedgerEntries`.
- If those entries were last modified at or before L, the vault's next leaf index MUST
  equal the indexer's leaf count, and the vault's current root MUST equal the
  indexer's root.
- If they were modified after L, the indexer first ingests up to that ledger and then
  compares again.
- Any other difference is a mismatch. The indexer stops serving `leaves`,
  `nullifiers` and `deposits`, keeps ingesting, and alerts. It serves again only after
  a rebuild from scratch reconciles.

This catches a stale restore of the vault's storage, a lying or lagging RPC provider,
and indexer bugs.

### API

Responses are JSON with binary values in lowercase hex. The API is read-only, needs
no credentials, sets no cookies and allows any origin.

| Endpoint | Returns |
| --- | --- |
| `GET /v1/health` | identity and readiness, see Health |
| `GET /v1/leaves?page=N` | leaves `1024*N` to `1024*N + 1023`, each with index, commitment, ciphertext, ledger and transaction hash; a full page never changes and is served with a long cache lifetime |
| `GET /v1/nullifiers?since_ledger=L&cursor=C` | every nullifier spent at or after ledger L, with its ledger and transaction hash, in chain order, at most 4,096 per response, with the next cursor and the ledger the answer is complete to |
| `GET /v1/deposits` | the whole entry queue: for each pending deposit its ID, depositor, amount, `created_at`, earliest admission time, attestation and flag reason; plus the deposits resolved in the last 7 days, with outcome and leaf indices |
| `GET /v1/stats` | leaf count, admitted deposits, distinct depositors of admitted deposits, pending deposits |
| `GET /v1/stream` | server-sent events: one wake event per ledger that changed the vault, carrying only the ledger, leaf count and nullifier count |

- Pages are aligned. A client asks for every page from the last one it completed, so
  its requests show how far it has synced, never which leaves it owns (F-05).
- There is no endpoint for a single leaf, path or nullifier. The leaves a client
  fetched would reveal which outputs passed its view tag, and the nullifiers it asked
  about would reveal its notes (F-04).
- There is no Merkle path endpoint. Clients keep their own tree.

### Health

`GET /v1/health` returns `ready`, `vault`, `network_id`, `deploy_ledger`,
`latest_ledger`, `ingested_ledger`, `reconciled_ledger`, `leaf_count`, `root`,
`nullifier_count` and `pending_count`, with status 503 when not ready. The indexer is
ready only when all of these hold:
- its probe of the RPC's latest ledger succeeded in the last 30 seconds; a failed
  probe means not ready, never "no lag" (F-22);
- `ingested_ledger` is within 12 ledgers, about one minute, of the latest ledger;
- the last reconciliation matched, and no gap or fault is open.

A response that is not ready carries one code, `probe_failed`, `lagging`, `mismatch`
or `fault`, and no internal error text (F-22).

### Backups and rebuild (F-21)

Leaves exist only in events, and RPC keeps events for about seven days. The indexer
therefore keeps its own copies and can rebuild without them.
- Every raw vault event, with its ledger and transaction hash, is appended to an
  archive that is copied off the host daily. The database is dumped daily. A restore
  is tested at least every three months.
- On mainnet the indexer can rebuild from scratch out of the public ledger-meta
  archive (`s3://aws-public-blockchain/v1.1/stellar/ledgers/pubnet`, SEP-54 layout),
  which holds the events of every ledger, and then from RPC for the recent window.
- Testnet has no public archive. There the indexer relies on its own archive and
  backups.
- A second indexer SHOULD run on another host against another RPC provider, so that
  clients can compare the two.

## Relayer

### Responsibilities

- Submit transfers and unshields as the transaction source, so that the user's account
  never appears in them.
- Quote a fee that covers its cost, paid in the pool asset.
- Screen every unshield destination before relaying it.
- Never relay a deposit. The relayer calls only `transact`, and rejects
  `ext_amount > 0`.

The relayer cannot change the recipient, amount, fee or outputs, which the proof binds
through `extDataHash` ([notes-and-circuit.md](notes-and-circuit.md)). Its code is
public, anyone can run one, and the SDK accepts any relayer that serves the same vault
([sdk.md](sdk.md)).

### Fee

```
cost  = p90 resource fee charged to this relayer's last 50 confirmed transact
        transactions (a configured bootstrap value until there are 50)
      + current p90 Soroban inclusion fee from getFeeStats
quote = roundUp(toAsset(cost) * (10000 + margin_bps) / 10000, tier)
```

- The fee covers cost. `margin_bps` covers failed submissions and price drift, is
  published in every quote, and MUST NOT exceed 1,000 (10 percent).
- The cost estimate learns only from transactions this relayer sent and saw
  confirmed, never from simulations or refused submissions (F-12).
- `toAsset` is the identity for XLM. For any other pool asset it converts with a
  configured price source, rounded up.
- `tier` comes from the deployment file: 0.01 XLM for the XLM vault. Tiered fees keep
  the fee in public ExtData from fingerprinting the moment of the quote (F-17).
- The fee is paid in the pool asset to the relayer's fee address, as part of the
  `transact` call.
- The vault's `max_fee` caps the fee. When the quote would exceed it, the relayer
  answers `unavailable` instead of quoting.
- A quote is valid for 5 minutes. The relayer accepts any fee at or above the lowest
  quote it published during the last 5 minutes, up to `max_fee`.

### Submission

`POST /v1/submit` runs these steps in order and stops at the first failure.
1. **Rate limits.** Per client at the proxy, and a global limit on simulations per
   minute, so failing submissions cannot run up RPC cost (F-12, F-15).
2. **Strict parsing.** Hex fields of exact length; both ciphertexts exactly 181 bytes
   (F-07); `ext.vault` and `ext.network_id` equal to the served vault and network;
   `ext_amount <= 0`; `ext.relayer` equal to the relayer's fee address; `fee` between
   the accepted quote and `max_fee` (F-11).
3. **Vault state.** A halted vault answers `unavailable`. A transfer while transfers
   are paused answers `paused`.
4. **In-flight dedupe.** If either nullifier belongs to a submission still in flight,
   the answer is `duplicate`. Otherwise both nullifiers stay in the in-flight set
   until the transaction is final (F-13).
5. **Screening.** An unshield's `recipient` goes to the screening service. A refusal
   answers `refused` with the public reason code; no answer within 5 seconds answers
   `unavailable`. The relayer fails closed.
6. **Simulation**, with a free channel account as source and `submitter`. A failed
   simulation answers `rejected`, without the RPC message.
7. **Signing and submission**, under the rules above. The response is 202 with the
   transaction hash as soon as the status is PENDING or DUPLICATE.
8. **Tracking** until the transaction is final. The channel and the nullifiers are
   released when it succeeds, fails, or its time bound passes unconfirmed.

A request MAY carry `not_before`, a time at most 24 hours ahead. The relayer then
holds it and runs step 6 at a random moment in the 10 minutes after `not_before`, so
the inclusion time does not follow the request time (F-17). The nullifiers stay in
flight during the hold.

Because the proof binds its ExtData `deadline`, a delayed request is built with a
deadline that covers `not_before` plus the jitter. The relayer rejects a request
whose deadline falls before that window. A delayed request still fails if its root
leaves the 256-root history before submission, which happens when more than 255
pairs are inserted in between. The client then proves again with a fresh root.

### Relay records

For each relayed transaction the relayer keeps the transaction hash, ledger, fee,
network fee charged and, for an unshield, the destination's screening result. A
record holds no client address and no request time. Records are kept for at least
five years ([screening-policy.md](screening-policy.md)), so that every fee can be
matched to its transaction and to the screening that preceded it.

### Accounts

- **Channel accounts:** at least four per relayer. Each is the source and the
  `submitter` of the transactions it sends, carries one transaction at a time, and
  holds at most a few days of network fees (F-14, F-16).
- **Fee address:** the `ext.relayer` of every relayed proof. It only receives, and its
  key is offline, so accrued fees are never reachable from a running server.
- Channels are refilled by hand from cold storage. The watcher alerts on a low channel
  balance and on any channel payment that is not the fee of its own transaction.

### API

| Endpoint | Returns |
| --- | --- |
| `GET /v1/health` | `ready`, `vault`, `network_id`, `fee_address`, `max_fee`, number of ready channels |
| `GET /v1/quote` | `fee`, `asset`, `tier`, `margin_bps`, `valid_until`, `fee_address`, `vault`, `network_id` |
| `POST /v1/submit` | body `{proof, ext, not_before?}`; 202 with `hash`, or an error code |
| `GET /v1/tx/{hash}` | `pending`, `success`, or `failed` with an error code, for a transaction this relayer submitted; 404 for any other hash |

Error codes: `bad_request`, `wrong_vault`, `fee_too_low`, `fee_above_cap`,
`duplicate`, `paused`, `refused`, `rejected`, `rate_limited`, `unavailable`.

## Keeper

Each vault has its own keeper account. Every call the keeper makes is permissionless,
so a stolen keeper key costs its float and nothing else.

- **TTL (F-24).** Every hour the keeper reads the remaining TTL of every ledger entry
  the vault depends on. It extends any entry within 30 days of expiry to just below
  the network's maximum entry TTL:
  - the vault instance, the tree entries and every pending deposit, through the
    vault's `bump_ttl`;
  - the vault's code, every nullifier entry, the vault's balance entry in the asset
    contract and the asset contract's instance, through `ExtendFootprintTTL`
    operations.

  Every pending deposit is included, flagged ones too, so that no refund claim
  archives.
- **Admission.** The keeper reads the entry queue from the chain, not from the
  indexer. When deposits become eligible ([vault.md](vault.md), Entry queue), it
  calls `admit` with their IDs in ascending order, in batches sized to the transaction
  resource limits.
- **Refunds.** It calls `refund` for a deposit that has been flagged for 24 hours and
  is still pending ([screening-policy.md](screening-policy.md)).
- **Alerts (F-24).** It alerts when its last complete TTL cycle is more than two hours
  old, when any entry is within 14 days of expiry, when an eligible deposit is not
  admitted within 10 minutes, when a call still fails after its retries, and when its
  own balance is low.

The keeper's integration tests run on a local network with short TTLs, and cover a
spend whose nullifier entry was archived and restored, and the cancel and refund of a
pending deposit that was archived.

## Screening service

The screening service is the association set provider (ASP): it holds a signer of the
vault's `asp` account and decides which deposits enter the tree. Its rules are public
in [screening-policy.md](screening-policy.md); this section covers how it runs.

### Responsibilities

- Screen every deposit when its `deposit_pending` event appears, which it reads from
  RPC, not from the indexer.
- Attest deposits, or flag them with a public reason code.
- Screen unshield destinations for the relayer.
- Accept compromised-address self-reports.
- Keep decision records and publish statistics.

### Sources

| Source | Applied to |
| --- | --- |
| CAP-77 frozen keys, read from the ledger | depositor, funders, destination |
| Sanctions lists with digital-currency addresses | depositor, funders, destination, and the source-chain sender of USDC bridged through CCTP |
| Published exploit and theft addresses | depositor, funders, destination |
| stellar.expert directory tags that mark an account as malicious | depositor, funders, destination |
| Self-reports and fraud reports | depositor, funders |
| Manual review | deposits at or above `large_deposit_threshold`, and deposits an automated rule refers |
| A KYT vendor, once its Stellar coverage is verified | all of the above |

Funders are the accounts that sent value to the depositor in the 30 days before the
deposit: one hop back, and two hops for a deposit at or above
`large_deposit_threshold`. Destinations are checked one hop back.

### Decisions on chain

- **First check.** The automated checks run within 10 minutes of `deposit_pending`. A
  deposit that fails is flagged at once with its reason code.
- **Manual review.** A deposit that needs review is reviewed by a person during its
  delay. If the reviewer refuses it, or the review is not finished before its re-check,
  it is flagged with reason 5.
- **Re-check and attestation.** In the last 10 minutes before a deposit becomes
  eligible, the automated checks run again with current sources. The service then
  calls `attest(up_to)` with the highest ID whose re-check passed, provided that every
  lower ID has passed its first check or is flagged. A flagged deposit inside the
  attested range is still never admitted. A lower deposit attested this way before its
  own re-check is still re-checked, and flagged if it fails, before it becomes
  eligible.
- **Fail closed.** If a required source is unreachable, or older than its maximum age,
  the service does not attest and it alerts. A deposit not yet attested waits, and its
  depositor can cancel. A deposit already attested that cannot be re-checked in time
  is flagged with reason 5. Nothing is admitted unchecked.
- **Unflag.** `unflag` only corrects a mistaken flag while the deposit is still
  pending. Every use is recorded.

### API

The relayer reaches one internal endpoint, which nginx does not route:

| Endpoint | Returns |
| --- | --- |
| `POST /internal/v1/screen` | `allow`, or `refuse` with a reason code, for one destination address |

Public endpoints:

| Endpoint | Returns |
| --- | --- |
| `GET /v1/policy` | the policy version, and the version and fetch time of every source |
| `GET /v1/stats` | the statistics listed in [screening-policy.md](screening-policy.md) |
| `POST /v1/self-report` | accepts a compromised-address report signed with that address's key |
| `GET /v1/check?address=A` | MAY be offered: whether an address would pass now, so a wallet can check before depositing |

### Keys and records

- The `asp` account's master key and recovery signers stay offline. The service holds
  one hot signer whose weight meets the threshold the vault's authorization needs, and
  a float of a few days of fees. Rotation happens on the account's signers
  ([vault.md](vault.md), Configuration).
- Decision records live in the service's own database, with encrypted backups off the
  host, for the retention [screening-policy.md](screening-policy.md) sets.

## Watcher

The watcher checks the vault from outside and pages a person. It holds no keys:
pausing or halting is a decision taken on the guardian's own signing devices. Its code
is public, and anyone can run one.

- It reads the chain through at least two independent RPC providers and alerts when
  they disagree.
- It builds its own copy of the tree and the nullifier set from events, and does not
  depend on the indexer.
- It evaluates every ledger and pages within two minutes of the ledger that triggered
  a check, through two independent channels. Governance events also go to a public
  channel.

| Check | Alerts when |
| --- | --- |
| Vault invariants ([vault.md](vault.md), Invariants) | `token.balance(vault) < tvl`; `tvl` differs from deposits minus refunds minus outflows recomputed from events; the next leaf index moves by anything other than two per admitted deposit or `transact`; a nullifier appears twice; a deposit ID is resolved twice; today's outflow exceeds `max_daily_outflow` |
| Root | the watcher's root differs from the vault's current root or from the indexer's |
| Outflow spike | unshields and fees within one hour exceed 20 percent of `max_daily_outflow`, or a single unshield exceeds `max_deposit` |
| Nullifier burst | more `transact` calls within 10 minutes than a configured multiple of the trailing daily rate |
| Governance | any `limits_queued`, `limits_applied`, `limits_cancelled`, `paused`, `halted` or `resumed` event; any change to the signers or thresholds of the guardian or `asp` account |
| Entry queue | an `attested` event earlier than the screening policy allows, which can mean a stolen `asp` key; every flag and unflag, as information |
| Freezes | a CAP-77 freeze that touches the vault, its code, its asset contract or any Cyphras service account |
| Liveness | an entry within 14 days of expiry; an eligible deposit not admitted after 10 minutes; a failing health endpoint |
| Hot accounts | a channel, keeper or `asp` account below its floor, or a payment out of it that is not the fee of its own transaction |

Vault events carry no amounts for outflows. The watcher reads them from the asset
contract's `transfer` events whose sender is the vault.

## Deployment

### Host and layout

- The services run on the private VPS behind nginx at `private.cyphras.com`, and
  replace the cy1 stack there. They SHOULD later move to a dedicated host with a
  non-root deploy user.
- Public paths are `/<network>/<asset>/indexer/`, `/<network>/<asset>/relayer/` and
  `/<network>/screening/`. The deployment file lists the URLs of every vault, and
  clients read them from there. The keeper, the watcher and the internal screening
  endpoint are not routed.
- Each service of each vault runs in its own container, under its own user, with a
  read-only root filesystem, bound to loopback. Each stateful service has its own
  Postgres database and credentials. Testnet and mainnet never share a database, a key
  or a secret.

### Build and release

- The source lives in `services/` of this repository.
- CI builds the images from signed git tags (`services-vX.Y.Z`), with a pinned Go
  toolchain and `-trimpath`, and publishes them by digest. The host pulls by digest.
  Nothing deployed is built on a workstation or copied by hand, so the running code
  can always be traced to a tag.
- Each deployment is recorded in `deployments/<network>.json`: tag, commit and image
  digest per service.

### Secrets

- Secrets are per-service files with mode 0400, owned by the service user and mounted
  read-only into that service's container only. There is no shared `.env` file, and no
  secret appears in a compose file or an environment listing (F-16).
- Guardian keys never touch a server. The relayer's fee address and the `asp` master
  key stay offline.

### nginx

- TLS only.
- `access_log off` for every service location. `error_log` at level `crit`, so that
  request-level errors, which carry the client address, are not written; `limit_req`
  rejections are logged below that level.
- Per-client rate limiting uses `limit_req` in shared memory. The proxy does not pass
  the client address upstream (no `X-Forwarded-For` or `X-Real-IP`), so the services
  never see it.
- The stream endpoint has its own location with buffering off.

### Logging policy

This policy is published with the services.

| Component | Logs | Never logs | Kept |
| --- | --- | --- | --- |
| nginx | startup and critical errors | client addresses, paths, user agents | 7 days |
| Indexer | ingest progress by ledger, reconciliation results, faults | anything about requests | 7 days |
| Relayer | hashes of the transactions it submitted, with status and fee | client addresses, request times, quote requests | 7 days; relay records 5 years |
| Keeper | its own transactions and results | not applicable | 7 days |
| Screening service | its decisions | anything about requests to its public endpoints | 7 days; decision records 5 years |
| Watcher | checks and alerts | not applicable | 30 days |

Container runtime logs rotate under the same limits.
