# Notes and circuit

## Poseidon2

`P2_n(x1..xn; tag)` is Poseidon2 over BN254 `Fr` in hash mode, with arity `n` and the
domain tag in the capacity element. Parameters:
- width `t = n + 1`, for `t` in {2, 3, 4};
- 8 full rounds and 56 partial rounds;
- S-box `x^5`;
- round constants from Horizen Labs' reference script.

`compress(l, r)` is the `t = 2` compression `(P(l, r) + (l, r))[0]` with no tag. It is
used only for Merkle nodes, so keyed hashes and tree nodes cannot collide. The
contract computes Poseidon2 with the CAP-0075 `poseidon2_permutation` host function.
The circuit, contract and SDK implementations MUST agree on the pinned vectors.

### Domain tags

| Tag | Use |
| --- | --- |
| 0x01 | note commitment |
| 0x02 | nullifier |
| 0x05 | `pk_d` fold |
| 0x06 | `nk` fold |
| 0x07 | `ak` fold |
| 0x08 | `g_d` fold |
| 0x09 | address fold of `g_d` and `pk_d` |
| 0x10 | `ivk` derivation |
| 0x11 | reserved: cy1 `r_d` derivation, MUST NOT be reused |
| 0x12 | `DiversifyHash` |

## Notes

A note is `(value, g_d, pk_d, rcm)`:
- `value`: an unsigned 64-bit amount in the pool asset's smallest unit (stroops for
  XLM);
- `(g_d, pk_d)`: the recipient address key;
- `rcm`: a fresh uniformly random field element, sampled by reducing 512 random bits
  mod the field order.

There is no asset field. Each vault holds one asset and carries its own `domain`.

```
addrFold = P2_2(fold(g_d; 0x08), fold(pk_d; 0x05); 0x09)
cm       = P2_3(value, addrFold, rcm; 0x01)
nf       = P2_3(cm, pos, nkFold; 0x02)
```

`pos` is the leaf index of `cm` in the tree. The nullifier binds the position, so
two equal commitments at different leaves nullify independently.

## Merkle tree

- Incremental tree of depth 20 (1,048,576 leaves), leaves are commitments.
- The empty leaf is `0`, and `zeros[i] = compress(zeros[i-1], zeros[i-1])`.
- Both commitments of a transaction or an admitted deposit are inserted together as
  one pair, which pushes exactly one new root.
- The vault keeps the last 256 roots, so a proof's root stays valid for 255 later
  insertions. The root `0` is rejected.
- A full tree rejects new insertions. Deploying a successor vault is the only way
  to continue.

## External data

```
ExtData {
  vault: Address              the vault contract this proof is for
  network_id: BytesN<32>      sha256 of the network passphrase
  deadline: u32               last ledger sequence at which the proof is accepted
  ext_amount: i128            > 0 deposit, < 0 withdrawal, 0 transfer
  fee: i128                   paid to relayer, 0 <= fee <= max_fee
  recipient: MuxedAddress     withdrawal destination (G, M or C)
  relayer: Address            fee recipient
  encrypted_output0: Bytes    exactly 181 bytes, see encryption.md
  encrypted_output1: Bytes    exactly 181 bytes
}

extDataHash  = keccak256(XDR(ScVal(ExtData))) mod p
publicAmount = (ext_amount - fee) mod p
```

The vault recomputes both values. `vault` and `network_id` close cross-deployment
and cross-network replay even if two vaults were ever given the same `domain`.

`deadline` bounds how long a relayer can sit on a proof. Clients set it about 120
ledgers (roughly 10 minutes) ahead and re-prove after it passes. None of these
fields touch the circuit: they enter the proof only through `extDataHash`. The
XDR encoding is the one `#[contracttype]` produces; the SDK MUST reproduce it
byte for byte, pinned by test vectors.

## Circuit statement

`Transaction(levels = 20, nIns = 2, nOuts = 2)`, Groth16 over BN254.

### Public inputs, in order

| # | Signal | Meaning |
| --- | --- | --- |
| 1 | `root` | a Merkle root from the vault's history |
| 2 | `publicAmount` | `(ext_amount - fee) mod p` |
| 3 | `extDataHash` | binds ExtData |
| 4 | `domain` | per-vault constant, injected by the vault |
| 5, 6 | `nf[0]`, `nf[1]` | input nullifiers |
| 7, 8 | `cmOut[0]`, `cmOut[1]` | output commitments |

### Private witnesses

- **Per input:** `value`, `ask`, `nsk`, `gd = (x, y)`, `q = (x, y)`, `rcm`, `pos`, and
  `pathElements[20]`.
- **Per output:** `value`, `gd = (x, y)`, `pkd = (x, y)`, and `rcm`.

### Constraints for each input `i`

1. `ask < L` and `nsk < L` (canonical scalars, so one key cannot yield two nullifiers).
2. `ak = ask * B` and `nk = nsk * B` by fixed-base multiplication. Fold both.
3. `ivk = ReduceModL(P2_2(akFold, nkFold; 0x10))`, a fully constrained reduction.
4. `q` is on the curve, `gd = 8 * q` (three doublings) and `gd.x != 0`. Together these
   put `gd` in the prime-order subgroup and exclude the identity.
   - This is required for soundness: with a low-order `gd`, `pk_d = ivk * gd` would
     hold for many keys, each giving a different nullifier for one note.
5. `pkd = ivk * gd` by variable-base multiplication over the 253 bits of `ivk`.
6. `cm = P2_3(value, addrFold(gd, pkd), rcm; 0x01)`. Matching an existing commitment
   is the ownership proof.
7. `pos` decomposes into exactly 20 bits. `nf[i] = P2_3(cm, pos, nkFold; 0x02)`.
8. The Merkle path from `cm`, using the bits of `pos`, reaches `root`. This is
   enforced only when `value != 0`: a zero-value input is a dummy that skips the root
   check but still produces a position-bound nullifier.
9. `value` decomposes into 64 bits.

### Constraints for each output `j`

10. `gd` and `pkd` are on the curve. The sender's software checks subgroup membership
    and the identity when parsing the address. A malformed output point only makes
    the sender's own note unspendable, because constraint 4 refuses it as an input.
11. `cmOut[j] = P2_3(value, addrFold(gd, pkd), rcm; 0x01)`.
12. `value` decomposes into 64 bits.

### Global constraints

13. `nf[0] != nf[1]`.
14. `sum(input values) + publicAmount == sum(output values)`. With 64-bit values the
    sums cannot wrap the field.
15. `extDataHash` and `domain` are each squared into an intermediate signal, so both
    are constrained and cannot be malleated.

### Budget

snarkjs needs `constraints + publicInputs + 1 <= 2^power`. With 8 public inputs, the
Hermez power-16 ptau allows at most 65,527 constraints. The count is measured at the
freeze; if it is exceeded, the power-17 ptau is used.
Compared with cy1, v2 drops the `r_d` hash, its mod-`L` reduction and a fixed-base
multiplication per input, and narrows the amount range from 248 to 64 bits. It adds
the cofactor check and two folds per note.

## Transactions

| Kind | ext_amount | Inputs | Outputs |
| --- | --- | --- | --- |
| Shield | `+amount` | two dummies | `[amount, 0]`, both to self |
| Transfer | `0` | one or two real notes, padded with a dummy | `[amount, change]` to recipient and self |
| Unshield | `-amount` | one or two real notes, padded with a dummy | `[change, 0]` to self |

- Every transaction has exactly two inputs and two outputs, and both ciphertexts have
  the same length.
- The wallet MUST randomize the order of the two outputs.
- Dummy inputs use the wallet's own `gd` and a fresh `rcm`.
