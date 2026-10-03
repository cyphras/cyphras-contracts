import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { F1Field } from "ffjavascript";
import { readR1cs } from "r1csfile";

export const ROOT = join(import.meta.dirname, "..");
export const CIRCOM_VERSION = "2.2.3";

// Changing the compiler or its flags changes the r1cs, so both are part of the freeze; --O2 is
// checked against the unsimplified system by scripts/check-o2.mjs.
export const OPTIMIZATION = "--O2";
export const FROZEN = {
  constraints: 31917,
  r1csSha256: "b838223d6261f12c35caf3c87d9f80a69ecaeed115251702fe8fefce07bb3fb5",
};

const LIBS = [join(ROOT, "lib"), join(ROOT, "node_modules")];
let versionChecked = false;

export function circom(
  source,
  outDir,
  { optimization = OPTIMIZATION, libs = LIBS, extra = [] } = {},
) {
  if (!versionChecked) {
    const version = execFileSync("circom", ["--version"], { encoding: "utf8" }).trim();
    if (version !== `circom compiler ${CIRCOM_VERSION}`) {
      throw new Error(`circom ${CIRCOM_VERSION} is required, found "${version}"`);
    }
    versionChecked = true;
  }
  const includes = libs.flatMap((dir) => ["-l", dir]);
  const args = [
    source,
    "--r1cs",
    "--wasm",
    "--sym",
    optimization,
    ...includes,
    "-o",
    outDir,
    ...extra,
  ];
  execFileSync("circom", args, { stdio: "pipe" });
}

export const sha256 = (path) => createHash("sha256").update(readFileSync(path)).digest("hex");

export const FIELD = new F1Field(
  21888242871839275222246405745257275088548364400416034343698204186575808495617n,
);

// Without an explicit field, r1csfile starts curve worker threads that keep the process alive.
export const loadR1cs = (path, options) => readR1cs(path, { F: FIELD, ...options });
