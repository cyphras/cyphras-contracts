import { mnemonicToSeedSync } from "@scure/bip39";
import { CyphrasError } from "../../src/errors.ts";
import { deriveStoreKey } from "../../src/keys.ts";
import { keySource } from "../../src/keysource.ts";
import { type KeyValueStore, MemoryStore } from "../../src/storage.ts";
import { type OpenOptions, PrivateWallet } from "../../src/wallet/wallet.ts";
import { MNEMONIC } from "../helpers.ts";
import { RPC, type World } from "./network.ts";
import { TrapdoorProver, trapdoorArtifacts } from "./trapdoor.ts";

export async function openWallet(
  world: World,
  account: number,
  storage: KeyValueStore = new MemoryStore(),
  prover = new TrapdoorProver(),
  options: Partial<OpenOptions> = {},
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
    ...options,
  });
}

export const confirmAll = (): true => true;

export function isError(code: string): (err: unknown) => boolean {
  return (err: unknown) => err instanceof CyphrasError && err.code === code;
}

/** The store key of a test account, to read and change its sealed state as an attacker could not. */
export function storeKeyOf(account: number): Uint8Array {
  return deriveStoreKey(mnemonicToSeedSync(MNEMONIC), "testnet", account);
}
