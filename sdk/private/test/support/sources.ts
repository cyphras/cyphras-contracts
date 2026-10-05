// Resolves the workspace's packages to their sources, so that a test that proves through the
// prover package runs it over the same core module as the test itself, with no build.
import { registerHooks } from "node:module";

const SOURCES: Readonly<Record<string, string>> = {
  "@cyphras/private": new URL("../../src/index.ts", import.meta.url).href,
  "@cyphras/private-prover-snarkjs": new URL(
    "../../../prover-snarkjs/src/index.ts",
    import.meta.url,
  ).href,
};

registerHooks({
  resolve(specifier, context, nextResolve) {
    const source = SOURCES[specifier];
    return source === undefined
      ? nextResolve(specifier, context)
      : { url: source, shortCircuit: true };
  },
});
