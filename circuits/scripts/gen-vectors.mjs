import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { keyVectors, noteVectors } from "../reference/vectors.mjs";

const OUT = join(import.meta.dirname, "..", "test", "vectors");

mkdirSync(OUT, { recursive: true });
for (const [name, vectors] of [
  ["keys.json", keyVectors()],
  ["notes.json", noteVectors()],
]) {
  writeFileSync(join(OUT, name), JSON.stringify(vectors, null, 2) + "\n");
  console.log(`wrote ${join(OUT, name)}`);
}
