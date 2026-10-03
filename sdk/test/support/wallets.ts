import { CyphrasError } from "../../src/errors.ts";
import { keySource } from "../../src/keysource.ts";
import { type KeyValueStore, MemoryStore } from "../../src/storage.ts";
import { PrivateWallet } from "../../src/wallet/wallet.ts";
import { MNEMONIC } from "../helpers.ts";
import { RPC, type World } from "./network.ts";
import { TrapdoorProver, trapdoorArtifacts } from "./trapdoor.ts";

export async function openWallet(
  world: World,
  account: number,
  storage: KeyValueStore = new MemoryStore(),
  prover = new TrapdoorProver(),
): Promise<PrivateWallet> {
  return PrivateWallet.open({
    deployment: world.deployment,
    allowUnpinnedDeployment: true,
    keys: keySource.mnemonic(MNEMONIC, { account }),
    prover,
    artifacts: trapdoorArtifacts,
    storage,
    rpcUrl: RPC,
    fetch: world.fetch,
    clock: world.clock,
    sleep: async () => {},
  });
}

export const confirmAll = (): true => true;

export function isError(code: string): (err: unknown) => boolean {
  return (err: unknown) => err instanceof CyphrasError && err.code === code;
}
