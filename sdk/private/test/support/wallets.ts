import { mnemonicToSeedSync } from "@scure/bip39";
import { CyphrasError } from "../../src/errors.ts";
import { deriveStoreKey } from "../../src/keys.ts";
import { keySource } from "../../src/keysource.ts";
import { type KeyValueStore, MemoryStore, SealedStore } from "../../src/storage.ts";
import type { TransactionSigner } from "../../src/vault/invoke.ts";
import { stateScope } from "../../src/wallet/state.ts";
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

/** The sealed records of a test account's state on the world's vault. */
export function sealedState(store: KeyValueStore, world: World, account = 0): SealedStore {
  const { vault, deployLedger } = world.deployment;
  return new SealedStore(store, storeKeyOf(account), stateScope(vault, deployLedger));
}

// A deposit made through the wallet, with the ID every RPC provider reported for it.
export async function shielded(
  wallet: PrivateWallet,
  amount: bigint,
  signer: TransactionSigner,
): Promise<{ readonly depositId: number; readonly txHash: string }> {
  const { depositId, txHash } = await wallet.shield({ amount, signer });
  if (depositId === undefined) throw new Error("the providers did not confirm the deposit's ID");
  return { depositId, txHash };
}
