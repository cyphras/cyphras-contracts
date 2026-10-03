# Encryption

Every transaction emits two output ciphertexts of exactly 181 bytes. Change and
dummy outputs are encrypted to the sender's own address, so size and count say
nothing about who was paid.

## Building an output

For a note `(value, d, pk_d, rcm)` with commitment `cm`, sent to the address
`(d, pk_d)`:

```
g_d   = DiversifyHash(d)
esk   = uniform scalar in [1, L), from 512 random bits reduced mod L
epk   = esk * g_d
S     = esk * pk_d                                   shared point

tag   = SHA-256("cyphras/v2/tag" || packPoint(S) || packPoint(epk))[0]
k_enc = SHA-256("cyphras/v2/enc" || packPoint(S) || packPoint(epk))
P_enc = 0x02 || d (11) || LE64(value) (8) || LE(rcm) (32)              52 bytes
C_enc = XChaCha20-Poly1305(k_enc, nonce = 0^24).seal(P_enc)            68 bytes

ock   = SHA-256("cyphras/v2/out" || ovk || LE(cm) || packPoint(epk))
P_out = packPoint(pk_d) (32) || LE(esk) (32)                          64 bytes
C_out = XChaCha20-Poly1305(ock, nonce = 0^24).seal(P_out)              80 bytes

blob  = packPoint(epk) (32) || tag (1) || C_enc (68) || C_out (80)     181 bytes
```

`ovk` is the sender's outgoing viewing key. A zero nonce is safe because both keys
are single use: `k_enc` depends on the fresh `epk`, and `ock` on `epk` and `cm`.

The vault rejects any ciphertext whose length is not 181 bytes.

## Receiving

For each blob, with incoming viewing key `ivk`:

1. Unpack `epk`. Reject it if it is off the curve, the identity, or outside the
   prime-order subgroup.
2. Compute `S = ivk * epk`, then the tag. If the tag differs, the output is not ours:
   stop. This skips the rest of the work for about 255 of every 256 outputs.
3. Derive `k_enc`, open `C_enc` and parse `P_enc`. A wrong version or a failed open
   means stop.
4. Recompute `g_d = DiversifyHash(d)`, `pk_d = ivk * g_d` and `cm`. Accept the note
   only if `cm` equals the on-chain commitment at that leaf. A note that decrypts but
   does not match is ignored, so no one can show a wallet funds it does not have.

## Outgoing recovery

A wallet restored from its seed recovers what it sent:
1. Derive `ock` from `ovk`, the leaf's `cm` and `epk`.
2. Open `C_out` to get `pk_d` and `esk`.
3. Compute `S = esk * pk_d`, then open `C_enc` and check `cm` as above.

A full viewing key carries `ovk`, so its holder sees outgoing notes as well.

## Payment disclosure

A sender or recipient can prove one payment to a third party, such as an exchange,
without handing over a viewing key. The disclosure is a JSON document:

```
{
  "version": 2,
  "network": "mainnet",
  "vault": "C...",
  "tx_hash": "...",
  "leaf_index": 1234,
  "address": "cy1...",
  "note": { "value": "1000000000", "rcm": "0x..." },
  "esk": "0x..."
}
```

The verifier:
1. Decodes the address to get `d` and `pk_d`, then recomputes `g_d` and `cm`.
2. Checks that `cm` is the commitment at `leaf_index`, emitted by `tx_hash` on that
   vault.
3. If `esk` is present, checks `esk * g_d` against the blob's `epk`. This shows the
   discloser built the output, which only its sender could have done.

The disclosure reveals that one note and nothing else.
