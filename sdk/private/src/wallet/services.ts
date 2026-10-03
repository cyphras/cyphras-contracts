import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex, utf8 } from "../bytes.ts";
import { CyphrasError } from "../errors.ts";
import type { Deployment, RelayerEndpoint } from "../deployments.ts";
import type { FetchLike } from "../net/http.ts";
import { IndexerClient } from "../net/indexer.ts";
import { RelayerClient } from "../net/relayer.ts";
import { SorobanRpc } from "../net/rpc.ts";
import { type VaultInstance, VaultReader } from "../vault/state.ts";

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

// Checks the RPC's network, the vault's code and domain as it reads them, and every service's
// identity; with a second RPC provider, the same of it. Anything pointing elsewhere is a mismatch,
// which refuses shields and spends; an unreachable service is only unavailable.
export async function verify(
  services: Services,
): Promise<{ verification: Verification; instance: VaultInstance | undefined }> {
  const { deployment, networkId } = services;
  let reason: string | undefined;
  const mismatch = (what: string): ServiceState => {
    reason ??= what;
    return "mismatch";
  };

  const provider = async (
    rpcClient: SorobanRpc,
    reader: VaultReader,
    what: string,
  ): Promise<{ rpc: ServiceState; vault: ServiceState; instance: VaultInstance | undefined }> => {
    const passphrase = await reachable(() => rpcClient.getNetworkPassphrase());
    const rpc: ServiceState =
      passphrase === undefined
        ? "unavailable"
        : passphrase === deployment.networkPassphrase
          ? "ok"
          : mismatch(`${what} serves another network`);
    let instance: VaultInstance | undefined;
    let vault: ServiceState = "unavailable";
    if (rpc === "ok") {
      try {
        instance = await reader.instance();
        if (instance.wasmHash !== deployment.vaultWasmHash)
          vault = mismatch("the vault runs other code");
        else if (instance.config.domain !== deployment.domain)
          vault = mismatch("the vault has another domain");
        else if (instance.config.token !== deployment.asset.contract)
          vault = mismatch("the vault holds another asset");
        else vault = "ok";
      } catch (err) {
        if (err instanceof CyphrasError && err.code === "deployment_mismatch")
          vault = mismatch(err.message);
        else if (!(err instanceof CyphrasError)) throw err;
      }
    }
    return { rpc, vault, instance };
  };

  const { rpc, vault, instance } = await provider(services.rpc, services.vault, "the RPC");
  let secondRpc: ServiceState | "not_set" = "not_set";
  if (services.second !== undefined) {
    const second = await provider(services.second.rpc, services.second.vault, "the second RPC");
    secondRpc = [second.rpc, second.vault].includes("mismatch")
      ? "mismatch"
      : second.rpc === "ok" && second.vault === "ok"
        ? "ok"
        : "unavailable";
  }

  const identity = (
    h: { vault: string; networkId: string } | undefined,
    what: string,
  ): ServiceState => {
    if (h === undefined) return "unavailable";
    if (h.vault !== deployment.vault || h.networkId !== networkId)
      return mismatch(`${what} serves another vault`);
    return "ok";
  };

  const indexers = await Promise.all(
    services.indexers.map(async (indexer) => {
      const health = await reachable(() => indexer.health());
      let state = identity(health, "an indexer");
      if (state === "ok" && health?.ready !== true) state = "unavailable";
      return { url: indexer.url, state };
    }),
  );

  const relayers = await Promise.all(
    services.relayers.map(async ({ client, pinned }) => {
      const health = await reachable(() => client.health());
      let state = identity(health, "a relayer");
      if (state === "ok" && pinned !== undefined && health?.feeAddress !== pinned.feeAddress) {
        state = mismatch("a relayer names another fee address");
      }
      if (state === "ok" && health?.ready !== true) state = "unavailable";
      return { url: client.url, state, feeAddress: health?.feeAddress };
    }),
  );

  const all = [
    rpc,
    vault,
    secondRpc,
    ...indexers.map((i) => i.state),
    ...relayers.map((r) => r.state),
  ];
  const state = all.includes("mismatch")
    ? "mismatch"
    : rpc === "ok" && vault === "ok"
      ? "verified"
      : "unverified";
  return {
    verification: {
      state,
      rpc,
      vault,
      secondRpc,
      secondRpcRecommended: deployment.recommendSecondRpc === true,
      indexers,
      relayers,
      reason,
    },
    instance,
  };
}
