# Keys and addresses

## Curve and encodings

All shielded keys live on Baby Jubjub, the twisted Edwards curve
`a*x^2 + y^2 = 1 + D*x^2*y^2` over the BN254 scalar field `Fr`, with `a = 168700`,
`D = 168696`. `B` is the standard prime-order generator `Base8`, `L` the order of the
prime subgroup and the cofactor is 8.

- `packPoint(P)`: 32 bytes, `y` little-endian with the sign of `x` in the top bit.
  Decoders MUST reject points that are not on the curve.
- `fold(P) = P2_2(P.x, P.y; tag)`: one field element per point, with a tag from the
  table in [notes-and-circuit.md](notes-and-circuit.md).
- `LE32(i)`: a 32-bit unsigned integer, little-endian.

## Seed

Every key below derives from a 64-byte `seed`. A wallet uses its BIP39 seed (the same
mnemonic as its Stellar keys). Other seed sources are defined in [sdk.md](sdk.md). The
seed never leaves the device.

## Key derivation

HKDF with SHA-512 (RFC 5869):

```
PRK        = HKDF-Extract(salt = "cyphras/v2/shielded", IKM = seed)
okm(label) = HKDF-Expand(PRK, info = network || "/" || account || "/" || label, L = 64)
```

- `network` is `mainnet` or `testnet` (ASCII).
- `account` is the decimal account index, matching the SEP-0005 index of the Stellar
  account it belongs to (`0`, `1`, ...).

```
ask = OS2IP(okm("ask")) mod L        spend authorizing key
nsk = OS2IP(okm("nsk")) mod L        nullifier key
ovk = okm("ovk")[0..32]              outgoing viewing key
dk  = okm("dk")[0..32]               diversifier key
sk  = okm("store")[0..32]            key for encrypting local wallet state
```

`store` never enters the protocol. It exists so local note caches can be encrypted
without reusing a protocol key.

A 512-bit value reduced mod `L` has negligible bias. If `ask` or `nsk` is zero the
derivation is retried with the label suffixed by `/1`, `/2`, ...; this has
probability about `2^-251` and exists only so the output is total.

Because the network name is in the info string, the same seed yields unrelated keys
and addresses on mainnet and testnet. Showing a testnet address in public reveals
nothing about the mainnet one.

Derived values:

```
ak  = ask * B                              akFold = fold(ak; 0x07)
nk  = nsk * B                              nkFold = fold(nk; 0x06)
ivk = P2_2(akFold, nkFold; 0x10) mod L     incoming viewing key
```

Spend authority is algebraic: knowledge of `ask` and `nsk` is what the circuit
checks. There is no separate signature.

## Diversified addresses

### DiversifyHash

`DiversifyHash(d)` maps an 11-byte diversifier `d` to a point of the prime-order
subgroup with no known discrete logarithm to `B`:

```
dInt = d as a little-endian integer              (< 2^88)
for ctr in 0..255:
    u   = P2_2(dInt, ctr; 0x12)
    den = 1 - D*u^2
    if den == 0: continue
    t   = (1 - a*u^2) / den
    if t is not a square in Fr: continue
    y   = sqrt(t), choosing the root whose canonical integer is even
    G   = 8 * (u, y)
    if G is the identity: continue
    return G
return FAIL
```

`FAIL` happens with probability about `2^-256`. A diversifier for which
`DiversifyHash` fails is invalid and MUST be skipped.

### Diversifiers

```
d_i = HMAC-SHA256(dk, "cyphras/v2/d" || LE32(i))[0..11]
```

The default address of an account uses the smallest index `i >= 0` whose `d_i` is
valid. A wallet MAY hand out further indices, for example one per payer. It need not
store the index: the diversifier travels inside each note plaintext, and decryption
needs only `ivk`.

### Address key

```
g_d  = DiversifyHash(d)
pk_d = ivk * g_d
```

Two addresses of one wallet, `(g_d1, ivk*g_d1)` and `(g_d2, ivk*g_d2)`, are
unlinkable under the decisional Diffie-Hellman assumption, because the discrete logs
of `g_d1` and `g_d2` are unknown. This replaces the cy1 construction
`g_d = H(d) * B`, where anyone could compute the ratio and link the addresses.

## Address encoding

A payment address is bech32m (BIP-350):

```
HRP     = "cy" (mainnet) | "cyt" (testnet)
payload = 0x02 || d (11 bytes) || packPoint(pk_d) (32 bytes)        44 bytes
```

The version byte `0x02` is new to v2, so cy1 prototype addresses (versions `0x00` and
`0x01`) are rejected rather than misread. An address is 80 characters on mainnet and
81 on testnet, within the 90-character bech32m limit.

A parser MUST reject:
- an HRP other than the active network's;
- an unknown version or a payload length other than 44;
- a `d` for which `DiversifyHash` fails;
- a `pk_d` that is off the curve, the identity, or outside the prime-order subgroup.

## Viewing keys

Viewing keys are bech32m without the 90-character limit.

| Key | HRP mainnet / testnet | Payload | Grants |
| --- | --- | --- | --- |
| Incoming viewing key | `cyivk` / `cytivk` | `0x02 \|\| dk \|\| LE(ivk)` (65 bytes) | Detect and read every incoming note and generate addresses. Cannot see spends or outgoing notes, cannot spend. |
| Full viewing key | `cyfvk` / `cytfvk` | `0x02 \|\| packPoint(ak) \|\| packPoint(nk) \|\| ovk \|\| dk` (129 bytes) | Everything the incoming key grants, plus spend detection (nullifiers need `nk`) and outgoing notes. Cannot spend. |

Exporting a viewing key reveals the whole history and future of the account to its
holder. Wallets SHOULD prefer per-payment disclosures ([encryption.md](encryption.md))
when one payment is all that needs proving.

## Test vectors

`vectors/keys.json` will pin, for the BIP39 test mnemonic `abandon` x11 + `about` with
an empty passphrase, on both networks and for accounts 0 and 1:
- `ask`, `nsk`, `ovk`, `dk`, `ak`, `nk` and `ivk`;
- `d_0` to `d_2`, with each `g_d`, `pk_d` and encoded address;
- both viewing keys.

The vectors are generated by the reference implementation during the circuit freeze
and checked in CI by the circuit tests, the contracts and the SDK.
