// Writes the npm README of the package in the working directory before npm packs it: a header for
// the package, then the SDK section of the repository's README. With --remove, deletes it after
// packing. Each package's README exists only in its tarball.
import { readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const REPO = "https://github.com/cyphras/cyphras-contracts";

const HEADERS: Readonly<Record<string, string>> = {
  "@cyphras/private":
    "Licensed under the Apache License 2.0. Proofs come from a prover: " +
    "[@cyphras/private-prover-snarkjs](https://www.npmjs.com/package/@cyphras/private-prover-snarkjs) " +
    "is the default one, and any implementation of the `Prover` interface works.",
  "@cyphras/private-prover-snarkjs":
    "**License: GPL-3.0-only.** This package runs snarkjs, which is under the GPL-3.0, and so " +
    "is itself under the GPL-3.0-only. An app that bundles it takes on the GPL-3.0 for that " +
    "bundle. The core, [@cyphras/private](https://www.npmjs.com/package/@cyphras/private), is " +
    "Apache-2.0 and accepts any implementation of its `Prover` interface.",
};

if (process.argv.includes("--remove")) {
  rmSync("README.md", { force: true });
} else {
  const { name, description } = JSON.parse(readFileSync("package.json", "utf8")) as {
    name: string;
    description: string;
  };
  const header = HEADERS[name];
  const root = readFileSync(join(import.meta.dirname, "..", "..", "README.md"), "utf8");
  const start = root.indexOf("\n## SDK\n");
  if (header === undefined || start < 0) {
    throw new Error(`no README header for ${name}, or no SDK section in the repository README`);
  }
  const end = root.indexOf("\n## ", start + 1);
  const section = root.slice(start + 1, end < 0 ? undefined : end + 1);
  writeFileSync(
    "README.md",
    `# ${name}\n\n${description}.\n\n${header}\n\nSource: ${REPO}\n\n${section}`,
  );
}
