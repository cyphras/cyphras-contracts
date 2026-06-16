import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

// Full testnet deploy: verifier (with the existing trusted-setup VK so client proofs stay valid),
// pool wasm, factory (admin chosen here), and one pool per (token, denomination). Writes the
// resulting addresses to deployments/testnet.json and prints the values the relayer needs.

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");

const IDENTITY = process.env.DEPLOY_IDENTITY;
if (!IDENTITY) {
  console.error("set DEPLOY_IDENTITY to the stellar CLI identity that signs the deploy");
  process.exit(1);
}
const NETWORK = "testnet";
const RPC = process.env.STELLAR_RPC_URL || "https://soroban-testnet.stellar.org";
const PASSPHRASE = "Test SDF Network ; September 2015";

const XLM_SAC = "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC";
const USDC_SAC = "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA";
const USDC_ISSUER = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5";
const DENOMS = ["1000000", "10000000", "100000000", "1000000000", "10000000000"];

const WASM_DIR = join(root, "stellar", "target", "wasm32v1-none", "release");
const VERIFIER_WASM = join(WASM_DIR, "cyphras_verifier.wasm");
const POOL_WASM = join(WASM_DIR, "cyphras_pool.wasm");
const FACTORY_WASM = join(WASM_DIR, "cyphras_factory.wasm");

// This script deploys the development trusted-setup VK, which is forgeable and testnet-only. Refuse to
// run against any non-testnet network so a copied or edited invocation can never put the dev VK on
// mainnet. Mainnet must deploy the Phase-2 MPC ceremony VK instead; see TRUST.md.
if (!PASSPHRASE.includes("Test SDF Network")) {
  console.error(
    "refusing to deploy: this script uses the development (forgeable) VK and is testnet-only. " +
      "mainnet must deploy the MPC ceremony VK; see TRUST.md.",
  );
  process.exit(1);
}

const vk = JSON.parse(readFileSync(join(root, "circuits", "build", "vk_parsed.json"), "utf-8"));

function run(args, opts = {}) {
  console.log(`\n$ stellar ${args.join(" ")}`);
  const out = execFileSync("stellar", args, {
    encoding: "utf-8",
    stdio: ["inherit", "pipe", "inherit"],
    ...opts,
  });
  // The CLI prints diagnostics to stderr and the result on stdout; the id is the last line.
  const lines = out.split("\n").map((l) => l.trim()).filter(Boolean);
  return lines[lines.length - 1].replace(/^"|"$/g, "");
}

async function latestLedger() {
  const res = await fetch(RPC, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "getLatestLedger" }),
  });
  const json = await res.json();
  return json.result.sequence;
}

console.log("Building contracts...");
execFileSync("cargo", ["build", "--target", "wasm32v1-none", "--release"], {
  cwd: join(root, "stellar"),
  stdio: "inherit",
});

const admin = run(["keys", "address", IDENTITY]);
console.log(`admin: ${admin}`);

const verifier = run([
  "contract", "deploy", "--wasm", VERIFIER_WASM,
  "--source", IDENTITY, "--network", NETWORK, "--",
  "--alpha_g1", vk.alpha_g1,
  "--beta_g2", vk.beta_g2,
  "--gamma_g2", vk.gamma_g2,
  "--delta_g2", vk.delta_g2,
  "--ic", JSON.stringify(vk.ic),
]);
console.log(`verifier: ${verifier}`);

// Capture the ledger before the factory exists so the relayer indexes from there and misses no pool.
const startLedger = await latestLedger();

const poolWasmHash = run([
  "contract", "upload", "--wasm", POOL_WASM,
  "--source", IDENTITY, "--network", NETWORK,
]);
console.log(`poolWasmHash: ${poolWasmHash}`);

const factory = run([
  "contract", "deploy", "--wasm", FACTORY_WASM,
  "--source", IDENTITY, "--network", NETWORK, "--",
  "--admin", admin,
  "--verifier", verifier,
  "--xlm_token", XLM_SAC,
  "--pool_wasm_hash", poolWasmHash,
]);
console.log(`factory: ${factory}`);

const pools = [];
for (const [asset, token] of [["XLM", XLM_SAC], ["USDC", USDC_SAC]]) {
  for (const denomination of DENOMS) {
    const pool = run([
      "contract", "invoke", "--id", factory,
      "--source", IDENTITY, "--network", NETWORK, "--",
      "create_pool", "--token", token, "--denomination", denomination,
    ]);
    pools.push({ asset, token, denomination, generation: 0, pool });
    console.log(`pool ${asset} ${denomination}: ${pool}`);
  }
}

const out = {
  network: NETWORK,
  networkPassphrase: PASSPHRASE,
  admin,
  xlmSac: XLM_SAC,
  usdcSac: USDC_SAC,
  usdcIssuer: USDC_ISSUER,
  poolWasmHash,
  contracts: { verifier, factory },
  pools,
};
writeFileSync(join(root, "deployments", "testnet.json"), JSON.stringify(out, null, 2) + "\n", "utf-8");

console.log("\nWrote deployments/testnet.json");
console.log("\nSet these in the relayer .env on the VPS:");
console.log(`FACTORY_ID=${factory}`);
console.log(`INDEXER_START_LEDGER=${startLedger}`);
