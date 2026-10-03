// The part of snarkjs this package uses; snarkjs ships no type declarations.
declare module "snarkjs" {
  export interface SnarkjsProof {
    pi_a: string[];
    pi_b: string[][];
    pi_c: string[];
    protocol: string;
    curve: string;
  }

  export const groth16: {
    fullProve(
      input: Record<string, unknown>,
      wasm: Uint8Array,
      zkey: Uint8Array,
      logger?: undefined,
      wtnsCalcOptions?: undefined,
      proverOptions?: { singleThread?: boolean },
    ): Promise<{ proof: SnarkjsProof; publicSignals: string[] }>;
    verify(vk: unknown, publicSignals: string[], proof: SnarkjsProof): Promise<boolean>;
  };

  export const zKey: {
    exportVerificationKey(zkey: Uint8Array): Promise<unknown>;
  };
}
