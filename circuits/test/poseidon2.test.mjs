import assert from "node:assert/strict";
import { compress, hash, permute } from "../reference/poseidon2.mjs";
import { harness, randomField } from "./helpers.mjs";

// Published permutation outputs for the inputs [0, 1, ..., t - 1].
const KNOWN_ANSWERS = {
  // HorizenLabs/poseidon2 plain_implementations, also pinned by the Soroban host tests
  3: [
    0x0bb61d24daca55eebcb1929a82650f328134334da98ea4f847f760054f4a3033n,
    0x303b6f7c86d043bfcbcc80214f26a30277a15d3f74ca654992defe7ff8d03570n,
    0x1ed25194542b12eef8617361c3ba7c52e660b145994427cc86296242cf766ec8n,
  ],
  // barretenberg Poseidon2Bn254ScalarFieldParams::TEST_VECTOR_OUTPUT
  4: [
    0x01bd538c2ee014ed5141b29e9ae240bf8db3fe5b9a38629a9647cf8d76c01737n,
    0x239b62e7db98aa3a2a8f6a0d2fa1709e7a35959aa6c7034814d9daa90cbac662n,
    0x04cbb44c61d928ed06808456bf758cbf0c18d1e15a7b6dbc8245fa7515d5e3cbn,
    0x2e11c5cff2a22c64d01304b778d78f6998eff1ab73163a35603f54794c30847an,
  ],
  // regression value; the t = 2 round constants match TaceoLabs/co-snarks in order
  2: [
    0x1d01e56f49579cec72319e145f06f6177f6c5253206e78c2689781452a31878bn,
    0x0d189ec589c41b8cffa88cfc523618a055abe8192c70f75aa72fc514560f6c61n,
  ],
};

// compress(7, 11) computed by the Soroban CAP-0075 poseidon2_permutation host function with the
// same parameters.
const HOST_COMPRESS_7_11 = 0x0960972bcfa9d858be6a1cca2c850d2eb0e5df1ad309192beeb95f8be328945fn;

const iota = (t) => Array.from({ length: t }, (_, i) => BigInt(i));

describe("Poseidon2", () => {
  describe("reference", () => {
    for (const t of [2, 3, 4]) {
      it(`matches the known answer for t = ${t}`, () => {
        assert.deepEqual(permute(iota(t)), KNOWN_ANSWERS[t]);
      });
    }

    it("matches the host function on compress(7, 11)", () => {
      assert.equal(compress(7n, 11n), HOST_COMPRESS_7_11);
    });
  });

  describe("circuit", () => {
    for (const t of [2, 3, 4]) {
      it(`Permutation(${t}) matches the reference`, async () => {
        const circuit = await harness(
          `permutation${t}`,
          "poseidon2/poseidon2_perm.circom",
          `Permutation(${t})`,
        );
        for (const inputs of [iota(t), Array.from({ length: t }, randomField)]) {
          const w = await circuit.witness({ inputs });
          const out = iota(t).map((i) => circuit.read(w, `main.out[${i}]`));
          assert.deepEqual(out, permute(inputs));
          assert.equal(circuit.violations(w), 0);
        }
      });
    }

    for (const n of [2, 3]) {
      it(`Poseidon2(${n}) matches the reference for every domain tag`, async () => {
        const circuit = await harness(
          `hash${n}`,
          "poseidon2/poseidon2_hash.circom",
          `Poseidon2(${n})`,
        );
        for (const tag of [0x01, 0x02, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x12]) {
          const inputs = Array.from({ length: n }, randomField);
          const w = await circuit.witness({ inputs, domainSeparation: tag });
          assert.equal(circuit.read(w, "main.out"), hash(inputs, tag));
        }
      });
    }

    it("PoseidonCompress matches the reference", async () => {
      const circuit = await harness(
        "compress",
        "poseidon2/poseidon2_compress.circom",
        "PoseidonCompress()",
      );
      for (const inputs of [
        [7n, 11n],
        [0n, 0n],
        [randomField(), randomField()],
      ]) {
        const w = await circuit.witness({ inputs });
        assert.equal(circuit.read(w, "main.out"), compress(...inputs));
      }
    });
  });
});
