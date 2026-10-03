// Bundles the SDK for browsers with esbuild and prints the minified and gzipped sizes, for the
// core alone and with the snarkjs prover. A Node built-in in the core fails the browser build.
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import { build } from "esbuild";

const SRC = join(import.meta.dirname, "..", "src");
const work = mkdtempSync(join(tmpdir(), "cyphras-size-"));
const withProver = join(work, "with-prover.ts");
writeFileSync(
  withProver,
  `export * from ${JSON.stringify(join(SRC, "index.ts"))};\n` +
    `export * from ${JSON.stringify(join(SRC, "prover-snarkjs", "index.ts"))};\n`,
);

async function size(entry: string): Promise<{ minified: number; gzipped: number }> {
  const result = await build({
    entryPoints: [entry],
    bundle: true,
    minify: true,
    format: "esm",
    platform: "browser",
    target: "es2022",
    write: false,
    logLevel: "error",
  });
  const bytes = result.outputFiles[0]?.contents ?? new Uint8Array();
  return { minified: bytes.length, gzipped: gzipSync(bytes).length };
}

const kib = (n: number): string => `${(n / 1024).toFixed(1)} KiB`;
for (const [name, entry] of [
  ["core", join(SRC, "index.ts")],
  ["core + snarkjs prover", withProver],
] as const) {
  const { minified, gzipped } = await size(entry);
  console.log(`${name}: ${kib(minified)} minified, ${kib(gzipped)} gzipped`);
}
