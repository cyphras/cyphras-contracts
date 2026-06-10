import {
  Keypair,
  TransactionBuilder,
  Operation,
  BASE_FEE,
  Contract,
  nativeToScVal,
  xdr,
  rpc,
  Networks,
} from "@stellar/stellar-sdk";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

// Submits the reveal the way the production relayer will: a throwaway ephemeral account
// (sponsored by the relayer) is the transaction source, and the relayer fee-bumps it. This
// keeps the relayer's main wallet off the reveal as the source, and the ephemeral is merged
// back afterwards to recover the sponsored reserve.

const here = dirname(fileURLToPath(import.meta.url));
const J = JSON.parse(readFileSync(join(here, "..", "build", "integration.json"), "utf-8")).reveal;
const POOL = JSON.parse(readFileSync(join(here, "..", "build", "integration.json"), "utf-8")).pool;

const RELAYER_SECRET = process.env.RELAYER_SECRET;
if (!RELAYER_SECRET) {
  console.error("set RELAYER_SECRET env var");
  process.exit(1);
}

const RPC = "https://soroban-testnet.stellar.org";
const NET = Networks.TESTNET;
const server = new rpc.Server(RPC);
const relayer = Keypair.fromSecret(RELAYER_SECRET);
const ephemeral = Keypair.random();

async function waitTx(hash) {
  for (let i = 0; i < 30; i++) {
    await new Promise((r) => setTimeout(r, 2000));
    const res = await server.getTransaction(hash);
    if (res.status === "SUCCESS") return res;
    if (res.status === "FAILED") throw new Error(`tx ${hash} failed`);
  }
  throw new Error(`tx ${hash} not confirmed`);
}

console.log("relayer:  ", relayer.publicKey());
console.log("ephemeral:", ephemeral.publicKey());

// 1. relayer sponsors a zero-balance ephemeral account
const relayerAcct = await server.getAccount(relayer.publicKey());
const sponsorTx = new TransactionBuilder(relayerAcct, {
  fee: String(parseInt(BASE_FEE) * 3),
  networkPassphrase: NET,
})
  .addOperation(Operation.beginSponsoringFutureReserves({ sponsoredId: ephemeral.publicKey() }))
  .addOperation(
    Operation.createAccount({ destination: ephemeral.publicKey(), startingBalance: "0" }),
  )
  .addOperation(Operation.endSponsoringFutureReserves({ source: ephemeral.publicKey() }))
  .setTimeout(60)
  .build();
sponsorTx.sign(relayer, ephemeral);
const sponsorRes = await server.sendTransaction(sponsorTx);
await waitTx(sponsorRes.hash);
console.log("sponsored ephemeral:", sponsorRes.hash);

// 2. ephemeral submits the reveal; relayer fee-bumps it
const ephemeralAcct = await server.getAccount(ephemeral.publicKey());
const contract = new Contract(POOL);
const revealOp = contract.call(
  "reveal",
  xdr.ScVal.scvBytes(Buffer.from(J.proof, "hex")),
  xdr.ScVal.scvBytes(Buffer.from(J.root, "hex")),
  xdr.ScVal.scvBytes(Buffer.from(J.nullifierHash, "hex")),
  xdr.ScVal.scvBytes(Buffer.from(J.amountHash, "hex")),
  nativeToScVal(J.recipient, { type: "address" }),
  nativeToScVal(J.relayer, { type: "address" }),
  nativeToScVal(BigInt(J.xlmFee), { type: "i128" }),
);
let revealTx = new TransactionBuilder(ephemeralAcct, { fee: BASE_FEE, networkPassphrase: NET })
  .addOperation(revealOp)
  .setTimeout(60)
  .build();
const sim = await server.simulateTransaction(revealTx);
if (rpc.Api.isSimulationError(sim)) throw new Error(`simulation failed: ${sim.error}`);
revealTx = rpc.assembleTransaction(revealTx, sim).build();
revealTx.sign(ephemeral);

const feeBump = TransactionBuilder.buildFeeBumpTransaction(
  relayer,
  String(parseInt(BASE_FEE) * 100),
  revealTx,
  NET,
);
feeBump.sign(relayer);
const revealRes = await server.sendTransaction(feeBump);
await waitTx(revealRes.hash);
console.log("reveal tx (source = ephemeral, fee-bumped by relayer):", revealRes.hash);

// 3. merge the ephemeral account back to the relayer to recover the reserve
const ephAcct2 = await server.getAccount(ephemeral.publicKey());
const mergeTx = new TransactionBuilder(ephAcct2, { fee: BASE_FEE, networkPassphrase: NET })
  .addOperation(Operation.accountMerge({ destination: relayer.publicKey() }))
  .setTimeout(60)
  .build();
mergeTx.sign(ephemeral);
const mergeFeeBump = TransactionBuilder.buildFeeBumpTransaction(
  relayer,
  String(parseInt(BASE_FEE) * 10),
  mergeTx,
  NET,
);
mergeFeeBump.sign(relayer);
const mergeRes = await server.sendTransaction(mergeFeeBump);
await waitTx(mergeRes.hash);
console.log("ephemeral merged back to relayer:", mergeRes.hash);
