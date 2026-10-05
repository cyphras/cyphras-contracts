// Bundles the packages for browsers with esbuild and prints the minified and gzipped sizes: the
// core, the snarkjs prover alone with the core left out, and both, which is what an app using the
// default prover ships. A Node built-in in a package fails the browser build.
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import { build } from "esbuild";

const ROOT = join(import.meta.dirname, "..");
const CORE = join(ROOT, "private", "src", "index.ts");
const PROVER = join(ROOT, "prover-snarkjs", "src", "index.ts");
const work = mkdtempSync(join(tmpdir(), "cyphras-size-"));
const both = join(work, "with-prover.ts");
writeFileSync(
  both,
  `export * from ${JSON.stringify(CORE)};\nexport * from ${JSON.stringify(PROVER)};\n`,
);

// The prover's import of the core resolves to the core's source, which is what "both" bundles, or
// stays out of the bundle when the core is external.
async function size(
  entry: string,
  external: string[] = [],
): Promise<{ minified: number; gzipped: number }> {
  const result = await build({
    entryPoints: [entry],
    bundle: true,
    minify: true,
    format: "esm",
    platform: "browser",
    target: "es2022",
    ...(external.length === 0 ? { alias: { "@cyphras/private": CORE } } : { external }),
    write: false,
    logLevel: "error",
  });
  const bytes = result.outputFiles[0]?.contents ?? new Uint8Array();
  return { minified: bytes.length, gzipped: gzipSync(bytes).length };
}

const kib = (n: number): string => `${(n / 1024).toFixed(1)} KiB`;
for (const [name, entry, external] of [
  ["@cyphras/private", CORE, []],
  ["@cyphras/private-prover-snarkjs alone", PROVER, ["@cyphras/private"]],
  ["both", both, []],
] as const) {
  const { minified, gzipped } = await size(entry, [...external]);
  console.log(`${name}: ${kib(minified)} minified, ${kib(gzipped)} gzipped`);
}
