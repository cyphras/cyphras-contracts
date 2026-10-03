import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";
import { compress, hash, permute } from "../../src/poseidon2.ts";
import { POSEIDON2_CONSTANTS } from "../../src/poseidon2-constants.ts";
import { CIRCOM_CONSTANTS, parseCircomConstants } from "../../scripts/poseidon2-constants.ts";

// Published permutation outputs for the inputs [0, 1, ..., t - 1], as pinned in
// circuits/test/poseidon2.test.mjs: Horizen Labs (t = 3), barretenberg (t = 4) and a regression
// value whose constants match TaceoLabs/co-snarks (t = 2).
const KNOWN_ANSWERS: Record<2 | 3 | 4, bigint[]> = {
  2: [
    0x1d01e56f49579cec72319e145f06f6177f6c5253206e78c2689781452a31878bn,
    0x0d189ec589c41b8cffa88cfc523618a055abe8192c70f75aa72fc514560f6c61n,
  ],
  3: [
    0x0bb61d24daca55eebcb1929a82650f328134334da98ea4f847f760054f4a3033n,
    0x303b6f7c86d043bfcbcc80214f26a30277a15d3f74ca654992defe7ff8d03570n,
    0x1ed25194542b12eef8617361c3ba7c52e660b145994427cc86296242cf766ec8n,
  ],
  4: [
    0x01bd538c2ee014ed5141b29e9ae240bf8db3fe5b9a38629a9647cf8d76c01737n,
    0x239b62e7db98aa3a2a8f6a0d2fa1709e7a35959aa6c7034814d9daa90cbac662n,
    0x04cbb44c61d928ed06808456bf758cbf0c18d1e15a7b6dbc8245fa7515d5e3cbn,
    0x2e11c5cff2a22c64d01304b778d78f6998eff1ab73163a35603f54794c30847an,
  ],
};

// compress(7, 11) from the Soroban CAP-0075 poseidon2_permutation host function.
const HOST_COMPRESS_7_11 = 0x0960972bcfa9d858be6a1cca2c850d2eb0e5df1ad309192beeb95f8be328945fn;

describe("Poseidon2", () => {
  it("embeds exactly the circuit's constants", () => {
    const circuit = parseCircomConstants(readFileSync(CIRCOM_CONSTANTS, "utf8"));
    for (const t of [2, 3, 4] as const) {
      const embedded = POSEIDON2_CONSTANTS[t];
      assert.deepEqual(embedded.full, circuit[t]?.full);
      assert.deepEqual(embedded.partial, circuit[t]?.partial);
      assert.deepEqual(embedded.diag, circuit[t]?.diag);
      assert.equal(embedded.full.length, 8);
      assert.equal(embedded.partial.length, 56);
    }
  });

  for (const t of [2, 3, 4] as const) {
    it(`matches the published permutation for t = ${t}`, () => {
      const input = Array.from({ length: t }, (_, i) => BigInt(i));
      assert.deepEqual(permute(input), KNOWN_ANSWERS[t]);
    });
  }

  it("matches the host function on compress(7, 11)", () => {
    assert.equal(compress(7n, 11n), HOST_COMPRESS_7_11);
  });

  it("puts the tag in the last state element", () => {
    assert.equal(hash([1n, 2n], 0x09), permute([1n, 2n, 9n])[0]);
    assert.equal(hash([1n, 2n, 3n], 0x01), permute([1n, 2n, 3n, 1n])[0]);
  });

  it("refuses widths the circuit does not define", () => {
    assert.throws(() => permute([1n]));
    assert.throws(() => permute([1n, 2n, 3n, 4n, 5n]));
  });
});
