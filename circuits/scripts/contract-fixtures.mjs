// Fixtures for the vault tests: the domain vectors, and real proofs of a scripted sequence of
// shields, an admission, a transfer and unshields, proved with the testnet-forgeable key against
// the tree the vault builds.
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { keccak_256 } from "@noble/hashes/sha3";
import { Account, Address, MuxedAccount, StrKey, nativeToScVal, xdr } from "@stellar/stellar-base";
import * as snarkjs from "snarkjs";
import { P } from "../reference/babyjub.mjs";
import { domain, domainVectors } from "../reference/domain.mjs";
import { MerkleTree, noteCommitment } from "../reference/notes.mjs";
import { alice, bob, dummy, note, spend, transactionInput } from "../test/fixtures.mjs";

const ROOT = join(import.meta.dirname, "..");
const WASM = join(ROOT, "build", "transaction_js", "transaction.wasm");
const ZKEY = join(ROOT, "build", "testnet-forgeable", "transaction.zkey");
const CONTRACTS = join(ROOT, "..", "contracts");
const VK = join(CONTRACTS, "verifier", "keys", "testnet-forgeable", "verification_key.json");
const OUT = join(CONTRACTS, "vault", "fixtures", "proofs.json");
const DOMAINS = join(ROOT, "test", "vectors", "domains.json");

const sha256 = (data) => createHash("sha256").update(data).digest();
const hex = (bytes) => Buffer.from(bytes).toString("hex");
const hex32 = (x) => "0x" + x.toString(16).padStart(64, "0");
const toField = (bytes) => BigInt("0x" + hex(bytes)) % P;

const PASSPHRASE = "Test SDF Network ; September 2015";
const NETWORK_ID = sha256(PASSPHRASE);
const ASSET = "native";
const DOMAIN = domain("testnet", ASSET);
// Far enough ahead that the tests can replay a proof long after it was first accepted.
const DEADLINE = 10_000_000;
const CIPHERTEXT_LEN = 181;

const seed = (label) => sha256(`cyphras/v2/fixtures/${label}`);
const VAULT = StrKey.encodeContract(seed("vault"));
const ACCOUNTS = {
  alice: StrKey.encodeEd25519PublicKey(seed("alice")),
  bob: StrKey.encodeEd25519PublicKey(seed("bob")),
  relayer: StrKey.encodeEd25519PublicKey(seed("relayer")),
  exchange: StrKey.encodeEd25519PublicKey(seed("exchange")),
  merchant: StrKey.encodeContract(seed("merchant")),
};
ACCOUNTS.exchange_muxed = new MuxedAccount(
  new Account(ACCOUNTS.exchange, "0"),
  "1234567890123",
).accountId();

// The XDR of ScVal(ExtData) as the vault's #[contracttype] encodes it: a map keyed by field name,
// with the keys in sorted order.
function extData({ extAmount, fee, recipient, relayer }) {
  const outputs = [randomBytes(CIPHERTEXT_LEN), randomBytes(CIPHERTEXT_LEN)];
  const fields = [
    ["deadline", xdr.ScVal.scvU32(DEADLINE)],
    ["encrypted_output0", xdr.ScVal.scvBytes(outputs[0])],
    ["encrypted_output1", xdr.ScVal.scvBytes(outputs[1])],
    ["ext_amount", nativeToScVal(extAmount, { type: "i128" })],
    ["fee", nativeToScVal(fee, { type: "i128" })],
    ["network_id", xdr.ScVal.scvBytes(NETWORK_ID)],
    ["recipient", new Address(recipient).toScVal()],
    ["relayer", new Address(relayer).toScVal()],
    ["vault", new Address(VAULT).toScVal()],
  ];
  const keys = fields.map(([key]) => key);
  assert.deepEqual(keys, [...keys].sort());
  const encoded = xdr.ScVal.scvMap(
    fields.map(([key, val]) => new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol(key), val })),
  ).toXDR();
  return {
    json: {
      vault: VAULT,
      network_id: hex(NETWORK_ID),
      deadline: DEADLINE,
      ext_amount: extAmount.toString(),
      fee: fee.toString(),
      recipient,
      relayer,
      encrypted_output0: hex(outputs[0]),
      encrypted_output1: hex(outputs[1]),
    },
    xdr: hex(encoded),
    hash: toField(keccak_256(encoded)),
  };
}

const field = (x) => BigInt(x);
const g1 = (p) => hex32(field(p[0])).slice(2) + hex32(field(p[1])).slice(2);
// The host orders each Fq2 coordinate as c1 || c0; snarkjs writes [c0, c1].
const g2 = (p) =>
  [p[0][1], p[0][0], p[1][1], p[1][0]].map((c) => hex32(field(c)).slice(2)).join("");

writeFileSync(DOMAINS, JSON.stringify(domainVectors(), null, 2) + "\n");
console.log(`wrote ${DOMAINS}`);

const vk = JSON.parse(readFileSync(VK, "utf8"));
assert.deepEqual(await snarkjs.zKey.exportVerificationKey(ZKEY), vk, "zkey does not match the VK");

async function prove(tree, spends, outputs, ext) {
  const input = transactionInput({
    root: tree.root(),
    publicAmount: field(ext.json.ext_amount) - field(ext.json.fee),
    extDataHash: ext.hash,
    domain: DOMAIN,
    spends,
    outputs,
  });
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
  assert.ok(await snarkjs.groth16.verify(vk, publicSignals, proof));
  const signals = publicSignals.map((s) => hex32(field(s)));
  return {
    a: g1(proof.pi_a),
    b: g2(proof.pi_b),
    c: g1(proof.pi_c),
    root: signals[0],
    public_amount: signals[1],
    ext_data_hash: signals[2],
    domain: signals[3],
    input_nullifiers: signals.slice(4, 6),
    output_commitments: signals.slice(6, 8),
  };
}

const tree = new MerkleTree();
let nextLeaf = 0n;
function insert(notes) {
  for (const n of notes) tree.set(nextLeaf++, noteCommitment(n));
  return hex32(tree.root());
}

async function shield(name, depositor, wallet, amount) {
  const outputs = [note(amount, wallet.address), note(0n, wallet.address)];
  const ext = extData({ extAmount: amount, fee: 0n, recipient: depositor, relayer: depositor });
  const proof = await prove(tree, [dummy(wallet), dummy(wallet)], outputs, ext);
  return {
    step: { name, call: "shield", caller: depositor, ext: ext.json, ext_xdr: ext.xdr, proof },
    outputs,
  };
}

async function transact(name, caller, spends, outputs, terms) {
  const ext = extData(terms);
  const proof = await prove(tree, spends, outputs, ext);
  const root_after = insert(outputs);
  return { name, call: "transact", caller, ext: ext.json, ext_xdr: ext.xdr, proof, root_after };
}

const steps = [];
const emptyRoot = hex32(tree.root());

const aliceShield = await shield("shield_alice", ACCOUNTS.alice, alice, 1_000_000_000n);
const bobShield = await shield("shield_bob", ACCOUNTS.bob, bob, 500_000_000n);
steps.push(aliceShield.step, bobShield.step);
steps.push({
  name: "admit",
  call: "admit",
  ids: [1, 2],
  root_after: insert([...aliceShield.outputs, ...bobShield.outputs]),
});
const [aliceFunds] = aliceShield.outputs;
const [bobFunds] = bobShield.outputs;

// A valid proof of a deposit that also spends a real note. The note is only in the current tree,
// never in the empty one, so the vault must refuse it as a shield.
const refused = [];
{
  const amount = 100_000_000n;
  const outputs = [note(1_000_000_000n + amount, alice.address), note(0n, alice.address)];
  const terms = { extAmount: amount, fee: 0n, recipient: ACCOUNTS.alice, relayer: ACCOUNTS.alice };
  const ext = extData(terms);
  const spends = [spend(alice, aliceFunds, 0n, tree.path(0n)), dummy(alice)];
  const proof = await prove(tree, spends, outputs, ext);
  refused.push({
    name: "shield_spending_a_note",
    call: "shield",
    after: "admit",
    caller: ACCOUNTS.alice,
    ext: ext.json,
    ext_xdr: ext.xdr,
    proof,
  });
}

// Alice pays Bob 30 XLM through the relayer, which takes 0.5 XLM.
const toBob = note(300_000_000n, bob.address);
const aliceChange = note(695_000_000n, alice.address);
steps.push(
  await transact(
    "transfer",
    ACCOUNTS.relayer,
    [spend(alice, aliceFunds, 0n, tree.path(0n)), dummy(alice)],
    [toBob, aliceChange],
    { extAmount: 0n, fee: 5_000_000n, recipient: ACCOUNTS.relayer, relayer: ACCOUNTS.relayer },
  ),
);

// Bob spends both of his notes into an exchange deposit address that carries a muxed ID.
steps.push(
  await transact(
    "unshield_muxed",
    ACCOUNTS.relayer,
    [spend(bob, bobFunds, 2n, tree.path(2n)), spend(bob, toBob, 4n, tree.path(4n))],
    [note(90_000_000n, bob.address), note(0n, bob.address)],
    {
      extAmount: -700_000_000n,
      fee: 10_000_000n,
      recipient: ACCOUNTS.exchange_muxed,
      relayer: ACCOUNTS.relayer,
    },
  ),
);

// Alice self-relays all of her change to a contract, paying no fee.
steps.push(
  await transact(
    "unshield_self",
    ACCOUNTS.alice,
    [spend(alice, aliceChange, 5n, tree.path(5n)), dummy(alice)],
    [note(0n, alice.address), note(0n, alice.address)],
    { extAmount: -695_000_000n, fee: 0n, recipient: ACCOUNTS.merchant, relayer: ACCOUNTS.alice },
  ),
);

// Two dummy inputs into two zero-value outputs: valid, and it moves no value.
steps.push(
  await transact(
    "zero_value",
    ACCOUNTS.relayer,
    [dummy(alice), dummy(alice)],
    [note(0n, alice.address), note(0n, alice.address)],
    { extAmount: 0n, fee: 0n, recipient: ACCOUNTS.relayer, relayer: ACCOUNTS.relayer },
  ),
);

mkdirSync(dirname(OUT), { recursive: true });
writeFileSync(
  OUT,
  JSON.stringify(
    {
      description:
        "Proofs from circuits/scripts/contract-fixtures.mjs with the testnet-forgeable key. " +
        "Field elements are 0x-prefixed big-endian hex; bytes and points are unprefixed hex in " +
        "the host encoding.",
      network_passphrase: PASSPHRASE,
      network_id: hex(NETWORK_ID),
      vault: VAULT,
      asset: ASSET,
      domain: hex32(DOMAIN),
      accounts: ACCOUNTS,
      empty_root: emptyRoot,
      steps,
      refused,
    },
    null,
    2,
  ) + "\n",
);
console.log(`wrote ${OUT}`);
await globalThis.curve_bn128?.terminate();
