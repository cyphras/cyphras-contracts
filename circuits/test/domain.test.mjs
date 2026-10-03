import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { domainVectors } from "../reference/domain.mjs";

describe("domain vectors", () => {
  it("domains.json matches the reference implementation", () => {
    const file = join(import.meta.dirname, "vectors", "domains.json");
    assert.deepEqual(JSON.parse(readFileSync(file, "utf8")), domainVectors());
  });
});
