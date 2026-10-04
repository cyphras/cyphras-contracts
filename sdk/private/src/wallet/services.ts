import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex, utf8 } from "../bytes.ts";
import { CyphrasError } from "../errors.ts";
import type { Deployment, RelayerEndpoint } from "../deployments.ts";
import type { FetchLike } from "../net/http.ts";
import { IndexerClient } from "../net/indexer.ts";
import { RelayerClient } from "../net/relayer.ts";
import { SorobanRpc } from "../net/rpc.ts";
import { VaultReader } from "../vault/state.ts";

export type ServiceState = "ok" | "mismatch" | "unavailable";

/** What the open-time checks of the pinned deployment found. */
export interface Verification {
  readonly state: "verified" | "mismatch" | "unverified";
  readonly rpc: ServiceState;
  readonly vault: ServiceState;
  // The second RPC provider and its view of the vault, when one is set, and whether the
  // deployment advises setting one.
  readonly secondRpc: ServiceState | "not_set";
  readonly secondRpcRecommended: boolean;
  readonly indexers: readonly { readonly url: string; readonly state: ServiceState }[];
  readonly relayers: readonly {
    readonly url: string;
    readonly state: ServiceState;
    readonly feeAddress: string | undefined;
  }[];
  // A public description of the first mismatch.
  readonly reason: string | undefined;
}

export interface Services {
  readonly deployment: Deployment;
  readonly networkId: string;
  readonly rpc: SorobanRpc;
  readonly vault: VaultReader;
  // The vault as a second RPC provider reads it, when one is set.
  readonly second: { readonly rpc: SorobanRpc; readonly vault: VaultReader } | undefined;
  readonly indexers: readonly IndexerClient[];
  readonly relayers: readonly {
    readonly client: RelayerClient;
    readonly pinned: RelayerEndpoint | undefined;
  }[];
  readonly fetch: FetchLike;
}

function networkIdOf(passphrase: string): string {
  return bytesToHex(sha256(utf8(passphrase)));
}

export function createServices(
  deployment: Deployment,
  rpcUrl: string,
  fetchFn: FetchLike,
  indexerUrls: readonly string[] | undefined,
  relayerUrls: readonly string[] | undefined,
  secondRpcUrl: string | undefined,
): Services {
  const rpc = new SorobanRpc(rpcUrl, fetchFn);
  const second = secondRpcUrl === undefined ? undefined : new SorobanRpc(secondRpcUrl, fetchFn);
  const pinnedRelayers = new Map(deployment.relayers.map((r) => [r.url, r]));
  return {
    deployment,
    networkId: networkIdOf(deployment.networkPassphrase),
    rpc,
    vault: new VaultReader(rpc, deployment.vault),
    second:
      second === undefined
        ? undefined
        : { rpc: second, vault: new VaultReader(second, deployment.vault) },
    indexers: (indexerUrls ?? deployment.indexers).map((url) => new IndexerClient(url, fetchFn)),
    relayers: (relayerUrls ?? deployment.relayers.map((r) => r.url)).map((url) => ({
      client: new RelayerClient(url, fetchFn),
      pinned: pinnedRelayers.get(url),
    })),
    fetch: fetchFn,
  };
}

const reachable = async <T>(probe: () => Promise<T>): Promise<T | undefined> => {
  try {
    return await probe();
  } catch (err) {
    if (err instanceof CyphrasError) return undefined;
    throw err;
  }
};

// What one check found, and a public description of a mismatch.
interface Checked {
  readonly state: ServiceState;
  readonly reason: string | undefined;
}

const ok: Checked = { state: "ok", reason: undefined };
const unavailable: Checked = { state: "unavailable", reason: undefined };
const mismatch = (reason: string): Checked => ({ state: "mismatch", reason });

// An RPC provider's network, and the vault's code, domain and asset as it reads them.
async function checkProvider(
  deployment: Deployment,
  rpc: SorobanRpc,
  reader: VaultReader,
  what: string,
  timeoutMs: number | undefined,
): Promise<{ readonly rpc: Checked; readonly vault: Checked }> {
  const passphrase = await reachable(() => rpc.getNetworkPassphrase(timeoutMs));
  if (passphrase === undefined) return { rpc: unavailable, vault: unavailable };
  if (passphrase !== deployment.networkPassphrase) {
    return { rpc: mismatch(`${what} serves another network`), vault: unavailable };
  }
  let vault: Checked = unavailable;
  try {
    const instance = await reader.instance(timeoutMs);
    if (instance.wasmHash !== deployment.vaultWasmHash)
      vault = mismatch("the vault runs other code");
    else if (instance.config.domain !== deployment.domain)
      vault = mismatch("the vault has another domain");
    else if (instance.config.token !== deployment.asset.contract)
      vault = mismatch("the vault holds another asset");
    else vault = ok;
  } catch (err) {
    if (err instanceof CyphrasError && err.code === "deployment_mismatch") {
      vault = mismatch(err.message);
    } else if (!(err instanceof CyphrasError)) {
      throw err;
    }
  }
  return { rpc: ok, vault };
}

function identity(
  services: Services,
  health: { readonly vault: string; readonly networkId: string } | undefined,
  what: string,
): Checked {
  if (health === undefined) return unavailable;
  if (health.vault !== services.deployment.vault || health.networkId !== services.networkId) {
    return mismatch(`${what} serves another vault`);
  }
  return ok;
}

// An indexer's identity, and whether it is ready.
async function checkIndexer(
  services: Services,
  indexer: IndexerClient,
  timeoutMs: number | undefined,
): Promise<Checked> {
  const health = await reachable(() => indexer.health(timeoutMs));
  const checked = identity(services, health, "an indexer");
  return checked.state === "ok" && health?.ready !== true ? unavailable : checked;
}

async function checkRelayer(
  services: Services,
  { client, pinned }: Services["relayers"][number],
  timeoutMs: number | undefined,
): Promise<Checked & { readonly feeAddress: string | undefined }> {
  const health = await reachable(() => client.health(timeoutMs));
  let checked = identity(services, health, "a relayer");
  if (checked.state === "ok" && pinned !== undefined && health?.feeAddress !== pinned.feeAddress) {
    checked = mismatch("a relayer names another fee address");
  }
  if (checked.state === "ok" && health?.ready !== true) checked = unavailable;
  return { ...checked, feeAddress: health?.feeAddress };
}

// What a verification found, from its checks: a mismatch anywhere refuses shields and spends, and
// its reason is the first in the order RPC, second RPC, indexers, relayers.
function verification(
  services: Services,
  first: { readonly rpc: Checked; readonly vault: Checked },
  second: { readonly rpc: Checked; readonly vault: Checked } | undefined,
  indexers: readonly Checked[],
  relayers: readonly (Checked & { readonly feeAddress: string | undefined })[],
): Verification {
  const secondRpc: ServiceState | "not_set" =
    second === undefined
      ? "not_set"
      : [second.rpc.state, second.vault.state].includes("mismatch")
        ? "mismatch"
        : second.rpc.state === "ok" && second.vault.state === "ok"
          ? "ok"
          : "unavailable";
  const all = [
    first.rpc,
    first.vault,
    ...(second === undefined ? [] : [second.rpc, second.vault]),
    ...indexers,
    ...relayers,
  ];
  const state = all.some((c) => c.state === "mismatch")
    ? "mismatch"
    : first.rpc.state === "ok" && first.vault.state === "ok"
      ? "verified"
      : "unverified";
  return {
    state,
    rpc: first.rpc.state,
    vault: first.vault.state,
    secondRpc,
    secondRpcRecommended: services.deployment.recommendSecondRpc === true,
    indexers: indexers.map((c, i) => ({
      url: (services.indexers[i] as IndexerClient).url,
      state: c.state,
    })),
    relayers: relayers.map((c, i) => ({
      url: (services.relayers[i] as Services["relayers"][number]).client.url,
      state: c.state,
      feeAddress: c.feeAddress,
    })),
    reason: all.find((c) => c.reason !== undefined)?.reason,
  };
}

// Checks the RPC's network, the vault's code and domain as it reads them, and every service's
// identity, all at once; with a second RPC provider, the same of it. Anything pointing elsewhere is
// a mismatch, which refuses shields and spends; a service that does not answer within `timeoutMs`
// per request is only unavailable.
export async function verify(services: Services, timeoutMs?: number): Promise<Verification> {
  const { deployment, second } = services;
  const [first, other, indexers, relayers] = await Promise.all([
    checkProvider(deployment, services.rpc, services.vault, "the RPC", timeoutMs),
    second === undefined
      ? undefined
      : checkProvider(deployment, second.rpc, second.vault, "the second RPC", timeoutMs),
    Promise.all(services.indexers.map((i) => checkIndexer(services, i, timeoutMs))),
    Promise.all(services.relayers.map((r) => checkRelayer(services, r, timeoutMs))),
  ]);
  return verification(services, first, other, indexers, relayers);
}

// Asks again the indexers a verification found unavailable, so one that was slow to answer is not
// passed over for good; one that now points elsewhere is a mismatch.
export async function recheckIndexers(
  services: Services,
  found: Verification,
  timeoutMs: number,
): Promise<Verification> {
  const indexers = await Promise.all(
    found.indexers.map(async (entry, i) =>
      entry.state === "unavailable"
        ? checkIndexer(services, services.indexers[i] as IndexerClient, timeoutMs)
        : { state: entry.state, reason: undefined },
    ),
  );
  const mismatched = indexers.find((c) => c.state === "mismatch");
  return {
    ...found,
    state: mismatched === undefined ? found.state : "mismatch",
    indexers: found.indexers.map((entry, i) => ({
      url: entry.url,
      state: (indexers[i] as Checked).state,
    })),
    reason: found.reason ?? mismatched?.reason,
  };
}
