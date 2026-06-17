import * as snarkjs from "snarkjs";
import { existsSync } from "node:fs";
import { argv, exit } from "node:process";

// Independent full-chain verification of a Phase-2 zkey. Anyone can run this to confirm a zkey
// (an intermediate contribution or the final beacon output) derives from the published circuit
// r1cs and the Hermez powers of tau. The log prints every contribution hash in the chain, which
// you match against the published transcript.
//   node verify.mjs <withdraw.r1cs> <powersOfTau28_hez_final_14.ptau> <some.zkey>

const logger = {
  info: (m) => console.log(m),
  debug: () => {},
  warn: (m) => console.warn(m),
  error: (m) => console.error(m),
};

const [, , r1cs, ptau, zkey] = argv;
if (!r1cs || !ptau || !zkey) {
  console.error("usage: node verify.mjs <r1cs> <ptau> <zkey>");
  exit(1);
}
for (const p of [r1cs, ptau, zkey]) {
  if (!existsSync(p)) {
    console.error(`not found: ${p}`);
    exit(1);
  }
}

const ok = await snarkjs.zKey.verifyFromR1cs(r1cs, ptau, zkey, logger);
console.log(ok ? "\nZKey Ok!\n" : "\nZKey verification FAILED\n");
exit(ok ? 0 : 1);
