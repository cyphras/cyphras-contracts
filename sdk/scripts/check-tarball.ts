// Packs both packages the way a release does, with lifecycle scripts on so prepack builds the
// package and writes its README, and fails unless each tarball holds the README, the license and
// the built files, and none of the test, env or source map files. Prints each tarball's npm
// shasum and file count to compare with what the registry shows after a publish.
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const ROOT = join(import.meta.dirname, "..");
const PACKAGES = ["@cyphras/private", "@cyphras/private-prover-snarkjs"];
const REQUIRED = ["package/README.md", "package/LICENSE", "package/package.json"];
const FORBIDDEN = /(^|\/)(test|tests|src)\/|\.map$|\.test\.|(^|\/)\.env|(^|\/)\.npmrc$/;

interface PackResult {
  filename: string;
  shasum: string;
  entryCount: number;
  files: { path: string }[];
}

const out = mkdtempSync(join(tmpdir(), "cyphras-pack-"));
const problems: string[] = [];
try {
  for (const name of PACKAGES) {
    const stdout = execFileSync(
      "npm",
      ["pack", "--workspace", name, "--ignore-scripts=false", "--json", "--pack-destination", out],
      { cwd: ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "inherit"] },
    );
    const [result] = JSON.parse(stdout.slice(stdout.indexOf("[\n"))) as PackResult[];
    if (result === undefined) throw new Error(`npm pack returned nothing for ${name}`);
    const paths = result.files.map((f) => `package/${f.path}`);
    for (const path of REQUIRED) {
      if (!paths.includes(path)) problems.push(`${name}: missing ${path}`);
    }
    if (!paths.some((p) => p.startsWith("package/dist/") && p.endsWith(".js"))) {
      problems.push(`${name}: no built files under package/dist/`);
    }
    for (const path of paths.filter((p) => FORBIDDEN.test(p))) {
      problems.push(`${name}: unexpected ${path}`);
    }
    console.log(
      `${name}: ${result.filename} shasum ${result.shasum}, ${result.entryCount} files, ` +
        `README ${paths.includes("package/README.md") ? "present" : "MISSING"}`,
    );
  }
} finally {
  rmSync(out, { recursive: true, force: true });
}

if (problems.length > 0) {
  console.error(problems.join("\n"));
  process.exit(1);
}
