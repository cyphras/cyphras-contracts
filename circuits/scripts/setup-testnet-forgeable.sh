#!/usr/bin/env bash
# Dev-only Groth16 phase 2 for testnet: a single local contribution. Whoever runs this knows the
# toxic waste and can forge proofs, so the keys it writes MUST NOT back a vault that holds value.
# Mainnet keys come only from the multi-party ceremony.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
R1CS="$ROOT/build/transaction.r1cs"
PTAU="$ROOT/build/ptau/powersOfTau28_hez_final_16.ptau"
OUT="$ROOT/build/testnet-forgeable"
SNARKJS="$ROOT/node_modules/.bin/snarkjs"

if [ ! -f "$R1CS" ]; then
  echo "missing $R1CS, run: npm run compile" >&2
  exit 1
fi

node "$ROOT/scripts/ptau.mjs"
mkdir -p "$OUT"

"$SNARKJS" groth16 setup "$R1CS" "$PTAU" "$OUT/transaction_0000.zkey"
"$SNARKJS" zkey contribute "$OUT/transaction_0000.zkey" "$OUT/transaction.zkey" \
  --name="testnet-forgeable" -e="$(head -c 64 /dev/urandom | od -An -tx1 | tr -d ' \n')"
rm "$OUT/transaction_0000.zkey"

"$SNARKJS" zkey verify "$R1CS" "$PTAU" "$OUT/transaction.zkey"
"$SNARKJS" zkey export verificationkey "$OUT/transaction.zkey" "$OUT/verification_key.json"

echo "FORGEABLE testnet keys written to $OUT"
