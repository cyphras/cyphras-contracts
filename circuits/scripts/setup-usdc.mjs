import {
  Keypair,
  TransactionBuilder,
  Operation,
  Asset,
  BASE_FEE,
  Networks,
  Horizon,
} from "@stellar/stellar-sdk";

// Prepares testnet accounts for a USDC private-send test: adds the USDC trustline to the
// recipient (so it can receive), and adds the trustline plus acquires USDC for the sender by
// swapping XLM through the DEX. Secrets come from SENDER_SECRET / RECIPIENT_SECRET env vars.

const horizon = new Horizon.Server("https://horizon-testnet.stellar.org");
const NET = Networks.TESTNET;
const USDC = new Asset("USDC", "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5");

const sender = Keypair.fromSecret(process.env.SENDER_SECRET);
const recipient = Keypair.fromSecret(process.env.RECIPIENT_SECRET);

async function submit(kp, buildOps) {
  const account = await horizon.loadAccount(kp.publicKey());
  const builder = new TransactionBuilder(account, { fee: BASE_FEE, networkPassphrase: NET });
  buildOps(builder);
  const tx = builder.setTimeout(60).build();
  tx.sign(kp);
  return horizon.submitTransaction(tx);
}

console.log("recipient: add USDC trustline");
await submit(recipient, (b) => b.addOperation(Operation.changeTrust({ asset: USDC })));

console.log("sender: add USDC trustline and buy 5 USDC with XLM");
await submit(sender, (b) =>
  b.addOperation(Operation.changeTrust({ asset: USDC })).addOperation(
    Operation.pathPaymentStrictReceive({
      sendAsset: Asset.native(),
      sendMax: "1000",
      destination: sender.publicKey(),
      destAsset: USDC,
      destAmount: "5",
      path: [],
    }),
  ),
);

const acct = await horizon.loadAccount(sender.publicKey());
const bal = acct.balances.find((x) => x.asset_code === "USDC");
console.log("sender USDC balance:", bal ? bal.balance : "0");
