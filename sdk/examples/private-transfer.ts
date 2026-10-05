// A private transfer on the Stellar testnet through the SDK's published packages. It creates two
// wallets from fresh mnemonics and prints their cyt1 addresses, funds a fresh account through
// Friendbot, shields XLM from it into the first wallet, waits for the vault to admit the deposit,
// pays the second wallet privately through the relayer and prints the second wallet's balance.
// With --unshield, the first wallet then withdraws to a fresh account.
//
// From sdk/, after `npm ci` and `npm run build` (Node.js 22.18 or later):
//
//   node examples/private-transfer.ts --addresses-only
//   CYPHRAS_ARTIFACTS=<directory or URL> node examples/private-transfer.ts [--unshield]
//
// CYPHRAS_ARTIFACTS holds the testnet circuit files transaction.wasm, transaction.zkey and
// verification_key.json; the SDK checks each against the hash the deployment pins. A deposit
// waits in the vault's entry queue for screening and its delay, about 10 minutes on testnet.
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { Keypair, type Transaction, TransactionBuilder } from "@stellar/stellar-base";
import {
  type ArtifactName,
  type ArtifactSource,
  type KeySource,
  MemoryStore,
  PrivateWallet,
  type TransactionSigner,
  keySource,
} from "@cyphras/private";
import { snarkjsProver } from "@cyphras/private-prover-snarkjs";

const RPC_URL = "https://soroban-testnet.stellar.org";
const XLM = 10_000_000n;
const FILES: Readonly<Record<ArtifactName, string>> = {
  wasm: "transaction.wasm",
  zkey: "transaction.zkey",
  vkey: "verification_key.json",
};

const args = new Set(process.argv.slice(2));
const xlm = (stroops: bigint): string => `${Number(stroops) / Number(XLM)} XLM`;
const minutesSince = (start: number): string => `${((Date.now() - start) / 60_000).toFixed(1)} min`;

const alice = keySource.random();
const bob = keySource.random();
const addressOf = (keys: KeySource): Promise<string> =>
  PrivateWallet.address({ network: "testnet", keys, storage: new MemoryStore() });
console.log("alice", await addressOf(alice));
console.log("bob  ", await addressOf(bob));
if (args.has("--addresses-only")) process.exit(0);

const where = process.env["CYPHRAS_ARTIFACTS"];
if (where === undefined) {
  throw new Error("set CYPHRAS_ARTIFACTS to the directory or URL of the testnet circuit files");
}
const artifacts: ArtifactSource = {
  async load(name) {
    const file = FILES[name];
    if (!/^https?:\/\//.test(where)) return new Uint8Array(await readFile(join(where, file)));
    const response = await fetch(new URL(file, where.endsWith("/") ? where : `${where}/`));
    if (!response.ok) throw new Error(`${file}: HTTP ${response.status}`);
    return new Uint8Array(await response.arrayBuffer());
  },
};
const prover = snarkjsProver({ artifacts });
const open = (keys: KeySource): Promise<PrivateWallet> =>
  PrivateWallet.open({
    deployment: "testnet/xlm",
    keys,
    prover,
    artifacts,
    storage: new MemoryStore(),
    rpcUrl: RPC_URL,
    singleInstance: true,
  });
const [sender, receiver] = [await open(alice), await open(bob)];

const depositor = Keypair.random();
const funded = await fetch(`https://friendbot.stellar.org/?addr=${depositor.publicKey()}`);
if (!funded.ok) throw new Error(`Friendbot: HTTP ${funded.status}`);
const { hash: fundingTx } = (await funded.json()) as { hash: string };
console.log("funded", depositor.publicKey(), "tx", fundingTx);
const signer: TransactionSigner = {
  publicKey: depositor.publicKey(),
  async signTransaction(envelope, passphrase) {
    const tx = TransactionBuilder.fromXDR(envelope, passphrase) as Transaction;
    tx.sign(depositor);
    return tx.toXDR();
  },
};

const limits = await sender.vaultLimits(depositor.publicKey());
const deposit = limits.minDeposit > 10n * XLM ? limits.minDeposit : 10n * XLM;
const shielded = await sender.shield({ amount: deposit, signer });
console.log("shield", xlm(deposit), "deposit", shielded.depositId, "tx", shielded.txHash);
const queued = Date.now();
for (;;) {
  await sender.sync();
  if ((await sender.balance()).spendable >= deposit) break;
  const [info] = await sender.deposits();
  if (info?.flag !== undefined || info?.state === "refunded" || info?.state === "failed") {
    throw new Error(`the deposit did not enter the pool: ${info.state}`);
  }
  const at = info?.earliestAdmission;
  const opens = at === undefined ? "" : `, admissible from ${new Date(at * 1000).toISOString()}`;
  console.log(`  ${minutesSince(queued)}: ${info?.state}, attested ${info?.attested}${opens}`);
  await sleep(30_000);
}
console.log("admitted after", minutesSince(queued));

const payment = 3n * XLM;
const sent = await sender.send({ to: receiver.generateAddress(), amount: payment, maxFee: XLM });
console.log("send", xlm(payment), "fee", xlm(sent.fee), "tx", sent.txHash);
for (;;) {
  await sender.sync();
  const plan = (await sender.plans()).find((p) => p.planId === sent.planId);
  if (plan?.state === "settled") break;
  if (plan?.state === "dead") throw new Error("the payment failed");
  await sleep(5_000);
}
await receiver.sync();
console.log("bob's balance", xlm((await receiver.balance()).spendable));

if (args.has("--unshield")) {
  const destination = Keypair.random().publicKey();
  const out = await sender.unshield({
    to: destination,
    amount: 2n * XLM,
    maxFee: XLM,
    confirm: (review) => {
      for (const warning of review.warnings) console.log("  warning:", warning.code);
      return true;
    },
  });
  console.log("unshield", xlm(2n * XLM), "to", destination, "tx", out.txHash);
  for (;;) {
    await sender.sync();
    const plan = (await sender.plans()).find((p) => p.planId === out.planId);
    if (plan?.state === "settled" || plan?.state === "queued") {
      console.log("unshield", plan.state);
      break;
    }
    await sleep(5_000);
  }
}
await prover.close();
