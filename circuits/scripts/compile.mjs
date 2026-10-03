import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { FROZEN, ROOT, circom, loadR1cs, sha256 } from "./circom.mjs";

const out = join(ROOT, "build");
mkdirSync(out, { recursive: true });
circom(join(ROOT, "src", "transaction.circom"), out);

const r1cs = join(out, "transaction.r1cs");
const { nConstraints } = await loadR1cs(r1cs, { loadConstraints: false, loadMap: false });
const digest = sha256(r1cs);
console.log(`${r1cs}: ${nConstraints} constraints, sha256 ${digest}`);
if (nConstraints !== FROZEN.constraints || digest !== FROZEN.r1csSha256) {
  console.error(
    "this is not the frozen circuit; update FROZEN in scripts/circom.mjs only on purpose",
  );
  process.exit(1);
}
