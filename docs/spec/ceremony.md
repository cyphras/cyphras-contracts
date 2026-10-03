# Ceremony

The v2 circuit, `Transaction(20, 2, 2)` ([notes-and-circuit.md](notes-and-circuit.md)),
needs a phase-2 Groth16 setup before any vault holds real value. This is the plan for
that setup. It reuses the process and the kit of the v1 mainnet ceremony
(`circuits/ceremony/mainnet/` and its `TRANSCRIPT.md`), which ran with five
contributors and a drand beacon.

## Why

Whoever knows a setup's secret randomness (the toxic waste) can forge proofs and drain
every vault that uses its key. A multi-party setup is safe if at least one contributor
generated their share in secret and destroyed it. The vault compiles its verifying key
in and can never replace it ([vault.md](vault.md), Verifier), so this ceremony is what
ensures that no single party can forge a proof.

## Scope

The circuit holds no network, asset or vault constant: `domain` is a public input, and
the vault ID and network ID enter through `extDataHash`. One ceremony therefore serves
every v2 vault on mainnet and testnet. Any change to the circuit after the ceremony
needs a new ceremony and new vaults, so the ceremony starts only after the freeze.

## Preconditions

- The circuit is frozen at a git tag. Its r1cs SHA-256 and constraint count are
  published, and the tamper suite, circomspect, the reference vectors and the circuit
  review pass on that tag.
- The kit is ported to `circuits/ceremony/v2/`, with the snarkjs version pinned in its
  lockfile. A full dry run on the frozen r1cs has passed, and its output is deleted,
  because one machine made all of it.
- At least three contributors have confirmed a slot, at least one of them external.

## Phase 1

- The Hermez perpetual powers of tau are reused, not generated. snarkjs needs
  `nConstraints + nPublic + 1 <= 2^power`. With 8 public inputs, power 16 covers up to
  65,527 constraints. A larger circuit uses power 17.
- The coordinator downloads `powersOfTau28_hez_final_16.ptau` (or `_17`) from any
  mirror, runs `snarkjs powersoftau verify`, records its SHA-256 and cross-checks it
  against an independently published value. Trust comes from the verification, not
  from the mirror. The file is already prepared for phase 2.
- `groth16 setup` on the frozen r1cs produces `transaction_0000.zkey`.

## Phase 2

### Contributors

- At least three contributors. At least one MUST be external: not employed by,
  contracted to or paid by Cyphras. Five or more is the target. One honest contributor
  is enough.
- The coordinator, Cyphras, relays the files and MAY contribute; its contribution
  counts as one.
- Names are recorded in the zkey and published forever. A contributor uses a
  recognizable name with a public handle, such as `Name (github: handle)`, never an
  email address.

### Relay

Hub and spoke, as in v1:
1. The coordinator sends contributor N the latest zkey and its SHA-256.
2. The contributor runs `contribute.mjs` with `EXPECTED_INPUT_SHA256` set, and SHOULD
   set `R1CS` and `PTAU` so the whole chain is verified before contributing. The script
   draws the entropy from the OS random generator in memory and zeroes it; the entropy
   is never typed, passed on a command line or written to disk.
3. The contributor returns the output zkey and publishes an attestation.
4. The coordinator runs `coordinator.mjs receive`, which verifies the file against the
   r1cs and the ptau and re-derives the contribution hash. The coordinator matches that
   hash with the attestation, and only then relays the file to the next contributor.

Contributors SHOULD use a freshly booted machine, stay offline while contributing, and
delete their files once the coordinator confirms receipt.

### Attestations

Each contributor publishes their own attestation, from their own account, in the
public ceremony thread: name, contribution hash (BLAKE2b-512), output zkey SHA-256,
and a short note on the machine used and how the entropy was destroyed. It is signed
with PGP, a signed commit, or a SEP-53 signature from a known Stellar key. The
coordinator links each attestation from the transcript and never publishes one on a
contributor's behalf.

### Beacon

- The beacon is a drand quicknet round. The coordinator announces the round number in
  the ceremony thread at least 24 hours before drand produces it, once the last
  contribution is scheduled.
- The round's randomness is fetched from at least three independent drand relays,
  which must agree, and is checked against the drand chain's public key.
- `coordinator.mjs beacon <randomness>` applies it to the last contribution, with
  `numIterationsExp = 10`, producing `transaction_final.zkey`, and verifies the result.
- If the last contribution is not verified before the announced round, the
  coordinator announces a new future round. A round is never chosen after its value
  is known.

### Failures

- A contribution that fails verification is rejected. The contributor may retry from
  the same input.
- A contributor who does not return within their slot is skipped. The next one
  continues from the last verified zkey.
- If the integrity of the chain is in doubt, the ceremony restarts from
  `transaction_0000.zkey`.

## Transcript

`circuits/ceremony/v2/TRANSCRIPT.md` records:
- the circuit: source tag and commit, constraint count, public inputs in order, circom
  and snarkjs versions, r1cs SHA-256;
- phase 1: file name, source URL, SHA-256, the verify result;
- every zkey: contributor, contribution hash, output SHA-256, attestation link;
- the beacon: drand network, round, the link to and time of its announcement, the
  randomness, the command;
- the result: final zkey SHA-256, `verification_key.json` SHA-256, the SHA-256 of the
  key bytes the vault compiles in, and the `zkey verify` result.

No entropy is recorded.

## Verification

Anyone can check the ceremony by recomputing values and comparing bytes, never by
trusting a published hash:
1. `node verify.mjs transaction.r1cs <ptau> transaction_final.zkey` prints `ZKey Ok!`
   and every contribution hash. Each hash must match a signed attestation.
2. Recompute the SHA-256 of every published file and compare it with the transcript.
3. Export the verifying key from the final zkey and compare it byte for byte with
   `verification_key.json`.
4. Rebuild the vault from its tag. The key bytes the build compiles in must equal the
   exported key, and the hash the build pins must equal the hash recomputed from those
   bytes.
5. The deployed vault's wasm hash must equal the hash of the reproducible build.

## CI checks

These run on every vault build and on the change that adds the ceremony output. Any
failure stops the build ([vault.md](vault.md), Verifier):
- `delta_2 != gamma_2`;
- neither `gamma_2` nor `delta_2` equals the G2 generator;
- the key is Groth16 over BN254, with 8 public inputs and 9 IC points;
- the key exported from the final zkey equals the committed `verification_key.json`
  byte for byte;
- the SHA-256 recomputed from the key equals the pin in the build;
- a proof made with the final zkey verifies in the contract tests.

## Publication

A GitHub release, `mainnet-ceremony-v2-<YYYY-MM-DD>`, holds the r1cs, the witness
generator, every zkey from `0000` to the final one, `verification_key.json`, the key
bytes the vault compiles in, `TRANSCRIPT.md` and a `SHA256SUMS` file. The ptau is not
re-hosted: its source and hash are in the transcript. `TRANSCRIPT.md` and the
verifying key are also committed to this repository; the zkeys and the ptau are not.

## Timeline

The v1 ceremony took about seven days from the kit to the published transcript. The
plan for v2 is the same length:

| Day | Step |
| --- | --- |
| 0 | Freeze tag; publish the r1cs hash and constraint count; open the ceremony thread with the schedule; verify the ptau; create `transaction_0000.zkey` |
| 1 to 5 | One contributor slot per day, each up to 24 hours and handed on as soon as it is verified |
| 4 or 5 | Announce the beacon round, at least 24 hours ahead |
| 6 | Verify the last contribution; apply the beacon; export the key; run the CI checks |
| 7 | Publish the release and the transcript; the vault build pins the key |

After publication, a testnet vault built with the final key runs every flow end to
end before the mainnet deployment. Testnet vaults deployed before the ceremony use a
single-party testnet key. That key is forgeable, is labelled as such, and never backs
a mainnet vault.
