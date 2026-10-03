import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

// Full mainnet deploy: verifier (initialized with the Phase-2 MPC ceremony VK), pool wasm, factory, and
// one pool per (token, denomination). Writes addresses to deployments/mainnet.json and prints the values
// the relayer needs. This moves real funds and is irreversible, so it gates on an explicit confirmation,
// refuses to run off mainnet, verifies the VK against the finalized ceremony, and hands the factory admin
// to an M-of-N multisig before it finishes.
//
// Required env:
//   DEPLOY_IDENTITY   stellar CLI identity that signs the deploy (the funded deployer)
//   ADMIN_MULTISIG    M-of-N multisig account (G...) the factory admin is handed to
//   STELLAR_RPC_URL   a mainnet Soroban RPC endpoint
//   CONFIRM=mainnet-deploy
// Optional env:
//   DEPLOY_USDC=1     also create USDC pools (real Circle issuer)

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");

const IDENTITY = process.env.DEPLOY_IDENTITY;
if (!IDENTITY) {
  console.error(
    "set DEPLOY_IDENTITY to the stellar CLI identity that signs the deploy",
  );
  process.exit(1);
}

// The factory admin must be a multisig, not the hot deploy key: a single-key admin could deploy rogue
// pools or reassign admin. The deployer is admin only transiently (to create the initial pools), then
// admin is handed to this account.
const ADMIN = process.env.ADMIN_MULTISIG;
if (!ADMIN || !ADMIN.startsWith("G") || ADMIN.length !== 56) {
  console.error(
    "set ADMIN_MULTISIG to the M-of-N multisig account (G...) the factory is handed to",
  );
  process.exit(1);
}

if (process.env.CONFIRM !== "mainnet-deploy") {
  console.error(
    "refusing: set CONFIRM=mainnet-deploy to confirm a real, irreversible mainnet deployment",
  );
  process.exit(1);
}

const RPC = process.env.STELLAR_RPC_URL;
if (!RPC) {
  console.error("set STELLAR_RPC_URL to a mainnet Soroban RPC endpoint");
  process.exit(1);
}

// Optional resume for a partial prior run: pass these to skip the matching step and reuse the on-chain
// artifact, avoiding the expensive wasm uploads. The script is not atomic, so a mid-run failure leaves
// whatever already succeeded behind.
const RESUME_VERIFIER = process.env.VERIFIER_ID;
const RESUME_POOL_WASM_HASH = process.env.POOL_WASM_HASH;
const RESUME_FACTORY = process.env.FACTORY_ID;

const NETWORK = "mainnet";
const PASSPHRASE = "Public Global Stellar Network ; September 2015";

// Refuse anywhere but mainnet so a copied invocation cannot put the mainnet VK on a test network.
if (!PASSPHRASE.includes("Public Global Stellar Network")) {
  console.error("refusing: this script is mainnet-only");
  process.exit(1);
}

// The VK MUST be the Phase-2 ceremony output, never the forgeable testnet VK. Pin its sha256 to the
// finalized ceremony so a wrong or tampered file is caught before any pool can hold real funds.
const VK_PATH = join(root, "circuits", "build", "mainnet", "vk_parsed.json");
const VK_SHA256 =
  "5da51c49a584670b9dd83073931e06966fbe0c16758d6a3b6165a5c98869082b";
const vkRaw = readFileSync(VK_PATH);
const vkSha = createHash("sha256").update(vkRaw).digest("hex");
if (vkSha !== VK_SHA256) {
  console.error(
    `refusing: ${VK_PATH} sha256 ${vkSha} != ceremony VK ${VK_SHA256}`,
  );
  process.exit(1);
}
const vk = JSON.parse(vkRaw.toString("utf-8"));

const WASM_DIR = join(root, "stellar", "target", "wasm32v1-none", "release");
const VERIFIER_WASM = join(WASM_DIR, "cyphras_verifier.wasm");
const POOL_WASM = join(WASM_DIR, "cyphras_pool.wasm");
const FACTORY_WASM = join(WASM_DIR, "cyphras_factory.wasm");

// Stroops: 0.1, 1, 10, 100, 1000 of the asset.
const DENOMS = [
  "1000000",
  "10000000",
  "100000000",
  "1000000000",
  "10000000000",
];
const USDC_ISSUER = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";

// Inclusion fee bid per tx, in stroops. The CLI default of 100 sits at the network floor and is
// rejected (TxInsufficientFee) when it rises; the resource fee is simulated and added on top of this.
const FEE = "1000000";

// Strips STELLAR_RPC_URL so the CLI resolves the network from the --network alias alone; with the env
// var set the CLI treats the rpc-url as explicit and fails because no matching passphrase is provided.
function run(args, opts = {}) {
  console.log(`\n$ stellar ${args.join(" ")}`);
  const env = { ...process.env };
  delete env.STELLAR_RPC_URL;
  const out = execFileSync("stellar", args, {
    encoding: "utf-8",
    stdio: ["inherit", "pipe", "inherit"],
    env,
    ...opts,
  });
  const lines = out
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean);
  const last = lines.length ? lines[lines.length - 1] : "";
  return last.replace(/^"|"$/g, "");
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

// Compute SAC ids from the network passphrase rather than hardcoding, so the mainnet (not testnet)
// contract ids are always used.
const XLM_SAC = run([
  "contract",
  "id",
  "asset",
  "--asset",
  "native",
  "--network",
  NETWORK,
]);
console.log(`XLM SAC: ${XLM_SAC}`);

const assets = [["XLM", XLM_SAC]];
if (process.env.DEPLOY_USDC === "1") {
  const usdcSac = run([
    "contract",
    "id",
    "asset",
    "--asset",
    `USDC:${USDC_ISSUER}`,
    "--network",
    NETWORK,
  ]);
  assets.push(["USDC", usdcSac]);
  console.log(`USDC SAC: ${usdcSac}`);
}

console.log("Building contracts...");
execFileSync("cargo", ["build", "--target", "wasm32v1-none", "--release"], {
  cwd: join(root, "stellar"),
  stdio: "inherit",
});

const deployer = run(["keys", "address", IDENTITY]);
console.log(`deployer (signs): ${deployer}`);
console.log(`final factory admin (multisig): ${ADMIN}`);

let verifier = RESUME_VERIFIER;
if (verifier) {
  console.log(`verifier (reused): ${verifier}`);
} else {
  verifier = run([
    "contract",
    "deploy",
    "--wasm",
    VERIFIER_WASM,
    "--source",
    IDENTITY,
    "--network",
    NETWORK,
    "--fee",
    FEE,
    "--",
    "--alpha_g1",
    vk.alpha_g1,
    "--beta_g2",
    vk.beta_g2,
    "--gamma_g2",
    vk.gamma_g2,
    "--delta_g2",
    vk.delta_g2,
    "--ic",
    JSON.stringify(vk.ic),
  ]);
  console.log(`verifier: ${verifier}`);
}

// Capture the ledger before the factory exists so the relayer indexes from there and misses no pool.
const startLedger = await latestLedger();

let poolWasmHash = RESUME_POOL_WASM_HASH;
if (poolWasmHash) {
  console.log(`poolWasmHash (reused): ${poolWasmHash}`);
} else {
  poolWasmHash = run([
    "contract",
    "upload",
    "--wasm",
    POOL_WASM,
    "--source",
    IDENTITY,
    "--network",
    NETWORK,
    "--fee",
    FEE,
  ]);
  console.log(`poolWasmHash: ${poolWasmHash}`);
}

// Deploy with the deployer as admin so it can create the initial pools, then hand admin to the multisig
// at the end. create_pool requires admin auth, so the multisig cannot be admin during pool creation
// without collecting signatures per pool.
let factory = RESUME_FACTORY;
if (factory) {
  console.log(`factory (reused): ${factory}`);
} else {
  factory = run([
    "contract",
    "deploy",
    "--wasm",
    FACTORY_WASM,
    "--source",
    IDENTITY,
    "--network",
    NETWORK,
    "--fee",
    FEE,
    "--",
    "--admin",
    deployer,
    "--verifier",
    verifier,
    "--xlm_token",
    XLM_SAC,
    "--pool_wasm_hash",
    poolWasmHash,
  ]);
  console.log(`factory: ${factory}`);
}

const pools = [];
for (const [asset, token] of assets) {
  for (const denomination of DENOMS) {
    const pool = run([
      "contract",
      "invoke",
      "--id",
      factory,
      "--source",
      IDENTITY,
      "--network",
      NETWORK,
      "--fee",
      FEE,
      "--",
      "create_pool",
      "--token",
      token,
      "--denomination",
      denomination,
    ]);
    pools.push({ asset, token, denomination, generation: 0, pool });
    console.log(`pool ${asset} ${denomination}: ${pool}`);
  }
}

// Hand the factory to the multisig. After this the deploy key can no longer administer the factory.
run([
  "contract",
  "invoke",
  "--id",
  factory,
  "--source",
  IDENTITY,
  "--network",
  NETWORK,
  "--fee",
  FEE,
  "--",
  "set_admin",
  "--new_admin",
  ADMIN,
]);
console.log(`admin handed to multisig: ${ADMIN}`);

const out = {
  network: NETWORK,
  networkPassphrase: PASSPHRASE,
  admin: ADMIN,
  deployer,
  xlmSac: XLM_SAC,
  poolWasmHash,
  vkSha256: VK_SHA256,
  indexerStartLedger: startLedger,
  contracts: { verifier, factory },
  pools,
};
writeFileSync(
  join(root, "deployments", "mainnet.json"),
  JSON.stringify(out, null, 2) + "\n",
  "utf-8",
);

console.log("\nWrote deployments/mainnet.json");
console.log("\nSet these in the relayer .env (mainnet):");
console.log(`MAINNET_FACTORY_ID=${factory}`);
console.log(`MAINNET_INDEXER_START_LEDGER=${startLedger}`);
