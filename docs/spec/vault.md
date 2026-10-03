# Vault contract

One vault per asset per network. The vault holds the asset through its Stellar Asset
Contract, keeps the commitment tree and the nullifier set, verifies proofs, screens
deposits through an entry queue, and enforces limits.

The vault has no upgrade function and no function that moves user funds other than
the ones described here. A fix ships as a new vault that users move to themselves.

## Configuration

Fixed at construction. `__constructor` runs atomically with deployment, so there is
no initialization race.

| Field | Meaning |
| --- | --- |
| `token` | Stellar Asset Contract of the pool asset |
| `domain` | `OS2IP(sha256("cyphras/v2/domain/" \|\| network \|\| "/" \|\| asset)) mod p`, canonical and nonzero. `network` is `mainnet` or `testnet`; `asset` is `native` for XLM or `CODE:ISSUER` for an issued asset (ASCII). The values are pinned in `vectors/domains.json`. |
| `guardian` | Stellar account (a multisig) holding the guardian powers below |
| `asp` | Stellar account that attests and flags deposits |
| `delay_small`, `delay_large` | seconds a deposit waits before admission |
| `limits` | initial limits, adjustable as described under Limits |

Rotating the keys behind `guardian` or `asp` happens on the Stellar accounts
themselves (signers and thresholds). The addresses stored in the vault never change.

## Entry points

### shield(proof, ext, depositor) -> id

Deposits enter a queue; they are not inserted into the tree yet.

1. `depositor.require_auth()`. Rejected while halted or while deposits are paused.
2. ExtData checks:
   - `ext_amount > 0` and `fee == 0`;
   - `recipient == relayer == depositor`;
   - `vault` is this contract and `network_id` is the ledger's network ID;
   - both ciphertexts are exactly 181 bytes.
3. Limits:
   - `ext_amount <= max_deposit`;
   - the depositor's total for the current UTC day plus `ext_amount` is at most
     `max_daily_per_depositor`;
   - `tvl + ext_amount <= tvl_cap`.
4. Proof checks, shared by both entry points (see Proof checks below).
5. Effects:
   - mark both nullifiers spent, emitting `new_nullifier` for each;
   - store `Pending(id) = {depositor, amount, commitments, ciphertexts, created_at}`;
   - increase `tvl` and the depositor's day total;
   - emit `deposit_pending`.
6. Pull `amount` from the depositor last.

### transact(proof, ext, submitter)

Transfers (`ext_amount == 0`) and unshields (`ext_amount < 0`).

1. `submitter.require_auth()`: the relayer, or the user when self-relaying an
   unshield. Rejected while halted. Transfers are also rejected while transfers are
   paused; unshields are not.
2. ExtData checks:
   - `ext_amount <= 0` and `0 <= fee <= max_fee`;
   - `vault` and `network_id` as in `shield`;
   - both ciphertexts are exactly 181 bytes.
3. Outflow: today's outflow plus `-ext_amount + fee` must be at most
   `max_daily_outflow`.
4. Proof checks.
5. Effects:
   - mark both nullifiers spent, emitting `new_nullifier` for each;
   - insert both output commitments, emitting `new_commitment` with each ciphertext;
   - decrease `tvl` and increase today's outflow by `-ext_amount + fee`;
   - emit `settled`.
6. Pay `-ext_amount` to `recipient` (unshield) and `fee` to `relayer`, last.
   `recipient` is a `MuxedAddress`, so an unshield can pay an exchange deposit
   address that carries a muxed ID. If the SDK version in use cannot transfer to a
   muxed address, the field falls back to `Address`; record that decision at the
   freeze.

### Proof checks

1. Every U256 input is canonical (`< p`). Both nullifiers and both commitments are
   present (arity exactly 2).
   - The two nullifiers differ, and so do the two output commitments. Equal outputs
     would let one transaction poison indexers that key leaves by commitment.
   - `ext.deadline` is at or after the current ledger sequence, so a withheld proof
     expires.
2. `root` is in the 256-root history. The tree has room for two leaves.
3. Neither nullifier is spent. A spent nullifier whose entry was archived is restored
   automatically when it appears in the transaction footprint, so the check still
   sees it as spent.
4. `extDataHash` and `publicAmount` recomputed from `ext` match the proof.
5. Groth16 verification with the stored `domain` injected as public input 4.

### Entry queue

| Function | Caller | Effect |
| --- | --- | --- |
| `attest(up_to)` | `asp` | Marks every deposit with `id <= up_to` as screened. Monotonic, and at most the last deposit ID. |
| `flag(id, reason)` | `asp` | Marks a pending deposit as refused, with a public reason code ([screening-policy.md](screening-policy.md)). |
| `unflag(id)` | `asp` | Clears a flag set by mistake, if the deposit is still pending. |
| `admit(ids)` | anyone | For each eligible deposit, inserts its two commitments, emits `new_commitment` and `deposit_admitted`, and deletes the pending entry. |
| `cancel(id)` | the depositor | Refunds a deposit that is not yet admitted, to the depositor. |
| `refund(id)` | anyone | Refunds a flagged deposit to its depositor. |

`attest(up_to)` asserts that every unflagged deposit with `id <= up_to` has passed
screening. The ASP MUST decide each of those deposits first: flag the refused ones,
then attest. A deposit it cannot decide in time is flagged with reason 5 rather than
attested.

`flag` and `unflag` apply only to pending deposits and work while the vault is
halted. Flagging an already flagged deposit replaces its reason.

A deposit is eligible for `admit` when it is not flagged, `id <= attested_up_to`, the
vault is not halted, and `now >= created_at + delay`. The delay is `delay_large` when
`amount >= large_deposit_threshold`, otherwise `delay_small`. The keeper admits in
ascending ID order.

Refunds always go to the depositor recorded at `shield` time and never anywhere
else. `cancel` and `refund` work while the vault is halted, so a pending deposit can
always leave. If the screening service stops answering, deposits simply wait, and
their depositors can cancel.

### Guardian

| Function | Effect |
| --- | --- |
| `set_pause(deposits, transfers)` | Stops or resumes `shield` and/or transfers. Unshields, cancels and refunds keep working. |
| `halt()` | Stops `shield`, `transact` and `admit` for up to 72 hours (`halted_until = now + 259200`). Allowed only when `now >= next_halt_at`. |
| `resume()` | Ends a halt early. |
| `set_limits(limits)` | Tightening (every field lower or equal) applies at once, except that `max_daily_outflow` can never decrease. Any loosening is queued and applies after 7 days. |
| `cancel_limits()` | Drops a queued loosening. |

When a halt ends, by expiry or by `resume`, `next_halt_at = end + 604800`. Users
therefore always get at least 7 days to unshield between two halts.

Exits cannot be throttled shut by tightening limits either:
- `max_daily_outflow` only ever goes up;
- the vault rejects any configuration where `7 * max_daily_outflow < tvl_cap`, at
  construction and on every limits change.

So a full pool can always drain within a week of outflow windows. Lowering `max_fee`
to zero stops relayers but not exits, because an unshield can be self-relayed with a
zero fee. A stolen guardian key therefore cannot freeze funds beyond one bounded halt.

The guardian cannot move funds, change the verifier, edit the tree, the nullifier set
or pending deposits, or act on a single user.

### Limits

`Limits { max_deposit, max_daily_per_depositor, tvl_cap, max_daily_outflow, max_fee,
large_deposit_threshold }`, all in the asset's smallest unit.

- `apply_limits()` can be called by anyone once a queued loosening is due.
- Day windows are `floor(ledger timestamp / 86400)`.
- Per-depositor day totals live in temporary storage keyed by `(depositor, day)`.
  The day in the key is what resets them; expiry only garbage-collects.

Proposed initial values for the XLM vault on mainnet:

| Limit | Value |
| --- | --- |
| `max_deposit` | 2,500 XLM |
| `max_daily_per_depositor` | 5,000 XLM |
| `tvl_cap` | 25,000 XLM |
| `max_daily_outflow` | 5,000 XLM |
| `max_fee` | 5 XLM |
| `large_deposit_threshold` | 500 XLM |
| `delay_small` / `delay_large` | 1 hour / 24 hours |

## Verifier

- The verifying key is compiled in from the ceremony output. Its SHA-256 is pinned at
  build time and recorded in the deployment file.
- The build fails if `delta == gamma`, or if `delta` or `gamma` equals the G2
  generator. These are the signatures of a skipped phase 2.
- Before pairing, the verifier checks that `A` and `C` are on G1 and `B` is in G2.
- `vk_x` is computed with the CAP-0080 multi-scalar multiplication.

## Storage

| Class | Entries |
| --- | --- |
| Instance | configuration, limits, queued limits, pause flags, `halted_until`, `next_halt_at`, `next_deposit_id`, `attested_up_to`, `tvl`, outflow window |
| Persistent | tree frontier, zero hashes, root ring, next leaf index; one entry per nullifier; one entry per pending deposit |
| Temporary | per-depositor day totals; the reentrancy lock |

- Pending deposits MUST be persistent. If a temporary entry expired, the depositor's
  refund claim would be destroyed.
- Every write extends the entry's TTL.
- The permissionless `bump_ttl(pending_ids)` extends the instance, the tree entries
  and the listed pending deposits. Nullifier entries are extended by the keeper with
  `ExtendFootprintTTL`.

Keys are a `#[contracttype]` enum, so clients and services can read state directly
with `getLedgerEntries` instead of simulating from a user's account:

| Key | Class | Value |
| --- | --- | --- |
| `Config` | instance | token, domain, guardian, asp, delays |
| `Limits`, `QueuedLimits` | instance | current limits; queued loosening and its ready time |
| `Status` | instance | pause flags, `halted_until`, `next_halt_at`, `next_deposit_id`, `attested_up_to`, `tvl`, outflow window |
| `Roots` | persistent | the 256-root ring, plus the index of the newest root |
| `Frontier`, `Zeros`, `NextLeaf` | persistent | incremental tree state |
| `Nullifier(U256)` | persistent | marker |
| `Pending(u64)` | persistent | a pending deposit |
| `DepositorDay(Address, u64)` | temporary | the depositor's total for that day |

## Read entry points

- `config()`, `limits()`, `status()`
- `current_root()`, `is_known_root(root)`, `next_leaf_index()`
- `is_spent(nullifier)`
- `pending(id)`

All are free of side effects, and they mirror the storage keys above.

## Events

All events use a single snake_case topic and map-shaped data.

| Event | Data |
| --- | --- |
| `deposit_pending` | id, depositor, amount, commitment0, commitment1, created_at |
| `deposit_flagged` / `deposit_unflagged` | id, reason |
| `attested` | up_to |
| `deposit_admitted` | id, leaf_index0, leaf_index1 |
| `deposit_refunded` | id, reason (0 = cancelled by the depositor) |
| `new_commitment` | index, commitment, encrypted_output |
| `new_nullifier` | nullifier |
| `settled` | ext_amount, fee, recipient, relayer. Every field is already visible in the token transfers; the event saves the watcher from joining them. |
| `paused` | deposits, transfers |
| `halted` | until |
| `resumed` | next_halt_at |
| `limits_queued` / `limits_applied` / `limits_cancelled` | limits, ready_at |

## Invariants

These are checked in tests after every call and by the watcher on mainnet:

1. `tvl` equals the sum of pending deposit amounts plus the value of unspent admitted
   notes. On chain this is checked as `token.balance(vault) >= tvl`.
2. The next leaf index only grows, by exactly two per admitted deposit or transact.
3. A nullifier, once spent, stays spent, including across archival and restore.
4. A deposit ID is admitted, cancelled or refunded at most once.
5. Today's outflow never exceeds `max_daily_outflow`.
6. `7 * max_daily_outflow >= tvl_cap`, and `max_daily_outflow` never decreases.
