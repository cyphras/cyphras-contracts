import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { PINNED_ARCHIVES, PINNED_DEPLOYMENTS } from "../../src/deployments.ts";
import { CommitmentTree } from "../../src/merkle.ts";
import { SorobanRpc } from "../../src/net/rpc.ts";
import { VaultReader } from "../../src/vault/state.ts";
import { ArchiveSource } from "../../src/wallet/archive.ts";
import { checkRoot } from "../../src/wallet/sync.ts";

// Reads the published archives and a public RPC of each network, which only answer reads; set
// CYPHRAS_ONLINE=1 to run it.
const online = process.env["CYPHRAS_ONLINE"] === "1";
const RPC_URLS = {
  "testnet/xlm": process.env["CYPHRAS_TESTNET_RPC"] ?? "https://soroban-testnet.stellar.org",
  "mainnet/xlm": process.env["CYPHRAS_MAINNET_RPC"] ?? "https://mainnet.sorobanrpc.com",
} as const;

for (const name of ["testnet/xlm", "mainnet/xlm"] as const) {
  const RPC_URL = RPC_URLS[name];
  describe(`archive sync: the published ${name} archive`, { skip: !online }, () => {
    for (const url of PINNED_ARCHIVES[name]) {
      it(`rebuilds the vault's tree from ${new URL(url).host} and RPC's events after it`, async () => {
        const deployment = PINNED_DEPLOYMENTS[name];
        assert.ok(deployment !== null);
        const fetchFn = (input: string, init?: RequestInit) => globalThis.fetch(input, init);
        const rpc = new SorobanRpc(RPC_URL, fetchFn);
        const vault = new VaultReader(rpc, deployment.vault);
        const source = new ArchiveSource({
          urls: [url],
          fetch: fetchFn,
          pin: {
            vault: deployment.vault,
            networkPassphrase: deployment.networkPassphrase,
            deployLedger: deployment.deployLedger,
          },
          rpcs: [rpc],
          vaults: [vault],
          since: deployment.deployLedger,
          leafCount: 0,
          lastLeafLedger: 0,
          windows: 1_000,
          eventPages: 100,
        });
        const { nullifiers } = await source.nullifiers(deployment.deployLedger);
        const tree = CommitmentTree.fromSnapshot({ leafCount: 0, upper: [], partial: [] });
        const { leaves } = await source.nextLeaves(tree);
        const view = await vault.view();
        tree.append(leaves.slice(0, view.roots.nextLeaf).map((l) => l.commitment));
        assert.equal(checkRoot(tree, view.roots).state, "verified");
        assert.ok(nullifiers.length > 0);
        assert.equal((await source.part()).tailFrom !== undefined, true);
      });
    }
  });
}
