import { type ArtifactPins, checkArtifactPins } from "./artifacts.ts";
import { computeDomain } from "./domain.ts";
import { fail } from "./errors.ts";
import { isAccountId, isContractId } from "./extdata.ts";
import { NETWORK_PASSPHRASES, type Network, isNetwork } from "./keys.ts";

/** A relayer of a deployment and the fee address its proofs must name. */
export interface RelayerEndpoint {
  readonly url: string;
  readonly feeAddress: string;
}

/**
 * Everything an SDK release pins for one vault, taken from deployments/<network>.json by the
 * release script.
 */
export interface Deployment {
  readonly id: string;
  readonly network: Network;
  readonly networkPassphrase: string;
  readonly vault: string;
  readonly asset: {
    // The Stellar Asset Contract of the pool asset.
    readonly contract: string;
    // The asset contract's name: "native" or "CODE:ISSUER".
    readonly name: string;
  };
  readonly domain: bigint;
  readonly deployLedger: number;
  // SHA-256 of the vault's wasm, lowercase hex.
  readonly vaultWasmHash: string;
  readonly artifacts: ArtifactPins;
  readonly indexers: readonly string[];
  readonly relayers: readonly RelayerEndpoint[];
  // Relayer fees are multiples of this, in the asset's smallest unit.
  readonly feeTier: bigint;
  // Wallets of this deployment are advised to set a second RPC provider, which must agree with the
  // first before a payment is declared dead or a tree it contradicts is taken. Every pinned
  // mainnet deployment sets it.
  readonly recommendSecondRpc?: boolean;
}

/** The deployments an SDK release can pin. */
export type DeploymentName = "mainnet/xlm" | "testnet/xlm";

function deepFreeze<T>(value: T): T {
  if (typeof value === "object" && value !== null && !Object.isFrozen(value)) {
    for (const inner of Object.values(value)) deepFreeze(inner);
    Object.freeze(value);
  }
  return value;
}

// No v2 vault is deployed yet. The release script fills these in from the deployment files;
// until then opening a wallet on either refuses. Frozen to the last nested value, so no code in
// the page can swap a pinned vault, artifact hash or service for another.
export const PINNED_DEPLOYMENTS: Readonly<Record<DeploymentName, Deployment | null>> = deepFreeze({
  "mainnet/xlm": null,
  "testnet/xlm": null,
});

const HEX64 = /^[0-9a-f]{64}$/;
const ASSET_NAME = /^(native|[A-Za-z0-9]{1,12}:G[A-Z2-7]{55})$/;

function checkServiceUrl(url: string, pinned: boolean): void {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return fail("invalid_argument", "a service URL is not a URL");
  }
  // Pinned services are reached over TLS only; tests may point an unpinned deployment at a mock.
  const allowed = pinned ? ["https:"] : ["https:", "http:"];
  if (!allowed.includes(parsed.protocol) || parsed.username !== "" || parsed.password !== "") {
    fail("invalid_argument", "a service URL must be https without credentials");
  }
}

export function checkDeployment(d: Deployment, pinned: boolean): void {
  const bad = (what: string): never => fail("invalid_argument", `deployment ${what} is invalid`);
  if (typeof d.id !== "string" || d.id.length === 0) bad("id");
  if (!isNetwork(d.network) || d.networkPassphrase !== NETWORK_PASSPHRASES[d.network]) {
    bad("network");
  }
  if (!isContractId(d.vault)) bad("vault");
  if (!isContractId(d.asset.contract) || !ASSET_NAME.test(d.asset.name)) bad("asset");
  if (d.domain !== computeDomain(d.network, d.asset.name)) bad("domain");
  if (!Number.isSafeInteger(d.deployLedger) || d.deployLedger <= 0) bad("deploy ledger");
  if (!HEX64.test(d.vaultWasmHash)) bad("vault wasm hash");
  checkArtifactPins(d.artifacts);
  if (d.indexers.length === 0 || d.relayers.length === 0) bad("service list");
  for (const url of [...d.indexers, ...d.relayers.map((r) => r.url)]) checkServiceUrl(url, pinned);
  for (const r of d.relayers)
    if (!isAccountId(r.feeAddress) && !isContractId(r.feeAddress)) bad("relayer");
  if (d.feeTier <= 0n) bad("fee tier");
  if (pinned && d.network === "mainnet" && d.recommendSecondRpc !== true) {
    bad("second RPC recommendation");
  }
}

// The pinned deployment of that name. A Deployment object instead of a name is accepted only
// with allowUnpinned, for tests and development against local vaults.
export function resolveDeployment(
  deployment: DeploymentName | Deployment,
  allowUnpinned: boolean,
): Deployment {
  if (typeof deployment === "string") {
    if (!Object.hasOwn(PINNED_DEPLOYMENTS, deployment)) {
      fail("invalid_argument", `unknown deployment ${deployment}`);
    }
    const pinned = PINNED_DEPLOYMENTS[deployment];
    if (pinned === null) {
      fail(
        "deployment_not_pinned",
        `this SDK release pins no vault for ${deployment}; private payments v2 is not deployed there yet`,
        { deployment },
      );
    }
    checkDeployment(pinned, true);
    return pinned;
  }
  if (!allowUnpinned) {
    fail(
      "deployment_not_pinned",
      "a deployment that this release does not pin needs allowUnpinnedDeployment",
    );
  }
  checkDeployment(deployment, false);
  return deployment;
}
