// A model of contracts/vault on the contracts branch: the entry points the SDK calls, their
// checks in the vault's order, the state they change and the events they emit. Proofs are
// verified for real against the trapdoor key.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { Address, MuxedAccount, StrKey, nativeToScVal, xdr } from "@stellar/stellar-base";
import { parseVaultErrors } from "../../scripts/vault-errors.ts";
import { bytesToHex, hexToBytes } from "../../src/bytes.ts";
import {
  type ExtData,
  extDataHash,
  fromHostProof,
  publicAmount,
  type TxProof,
} from "../../src/extdata.ts";
import { P } from "../../src/field.ts";
import { parseVerifyingKey, verifyGroth16 } from "../../src/groth16.ts";
import { EMPTY_ROOT, LEVELS, ZEROS } from "../../src/merkle.ts";
import { compress } from "../../src/poseidon2.ts";
import { TRAPDOOR_VK } from "./trapdoor.ts";

// The vault's error codes by name, read from the contract source the SDK's table is generated from.
const CODES = new Map(
  [
    ...parseVaultErrors(
      readFileSync(join(import.meta.dirname, "..", "fixtures", "vault-error.rs"), "utf8"),
    ),
  ].map(([code, name]) => [name, code]),
);
const code = (name: string): number => {
  const value = CODES.get(name);
  if (value === undefined) throw new Error(`the vault has no error ${name}`);
  return value;
};

export const ERROR = {
  Halted: code("Halted"),
  DepositsPaused: code("DepositsPaused"),
  TransfersPaused: code("TransfersPaused"),
  NonEmptyRoot: code("NonEmptyRoot"),
  BadAmount: code("BadAmount"),
  BadFee: code("BadFee"),
  BadParties: code("BadParties"),
  WrongVault: code("WrongVault"),
  WrongNetwork: code("WrongNetwork"),
  BadCiphertext: code("BadCiphertext"),
  DepositTooLarge: code("DepositTooLarge"),
  DepositorDailyLimit: code("DepositorDailyLimit"),
  TvlCapExceeded: code("TvlCapExceeded"),
  BadArity: code("BadArity"),
  NonCanonical: code("NonCanonical"),
  DuplicateNullifier: code("DuplicateNullifier"),
  DuplicateCommitment: code("DuplicateCommitment"),
  Expired: code("Expired"),
  UnknownRoot: code("UnknownRoot"),
  NullifierSpent: code("NullifierSpent"),
  ExtDataHashMismatch: code("ExtDataHashMismatch"),
  PublicAmountMismatch: code("PublicAmountMismatch"),
  InvalidProof: code("InvalidProof"),
  UnknownDeposit: code("UnknownDeposit"),
  NotFlagged: code("NotFlagged"),
  RefundTooEarly: code("RefundTooEarly"),
  ExceedsAdmittedValue: code("ExceedsAdmittedValue"),
  DepositTooSmall: code("DepositTooSmall"),
  ExceedsDailyOutflow: code("ExceedsDailyOutflow"),
  NotStranded: code("NotStranded"),
  NothingClaimable: code("NothingClaimable"),
  CannotReceive: code("CannotReceive"),
  VaultCannotPay: code("VaultCannotPay"),
};

export class VaultError extends Error {
  readonly code: number;
  constructor(code: number) {
    super(`Error(Contract, #${code})`);
    this.code = code;
  }
}

const refuse = (code: number): never => {
  throw new VaultError(code);
};

export interface Limits {
  minDeposit: bigint;
  maxDeposit: bigint;
  maxDailyPerDepositor: bigint;
  tvlCap: bigint;
  maxDailyOutflow: bigint;
  maxFee: bigint;
  largeDepositThreshold: bigint;
}

export interface Pending {
  depositor: string;
  amount: bigint;
  commitments: [bigint, bigint];
  ciphertexts: [Uint8Array, Uint8Array];
  createdAt: bigint;
  delay: bigint;
  flag: number | undefined;
  flaggedAt: bigint;
}

// An exit the vault owes: payout and fee are what is still owed, queuedPayout and queuedFee what
// was queued, and movedPayout and movedFee what claims moved back into the queue as the exits
// requeuedTo. requeuedFrom is the stranded exit a claim queued this one from.
export interface Exit {
  id: number;
  payout: bigint;
  fee: bigint;
  queuedPayout: bigint;
  queuedFee: bigint;
  movedPayout: bigint;
  movedFee: bigint;
  recipient: string;
  relayer: string;
  queuedAt: bigint;
  txHash: string;
  ledger: number;
  requeuedFrom: number | undefined;
  requeuedTo: number[];
}

export interface EmittedEvent {
  readonly ledger: number;
  readonly txHash: string;
  readonly topic: string;
  readonly fields: [string, xdr.ScVal][];
}

export interface Transfer {
  readonly from: string;
  readonly to: string;
  readonly amount: bigint;
}

export const map = (fields: [string, xdr.ScVal][]): xdr.ScVal =>
  xdr.ScVal.scvMap(
    [...fields]
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([key, val]) => new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol(key), val })),
  );
const u64 = (n: bigint | number): xdr.ScVal => xdr.ScVal.scvU64(new xdr.Uint64(BigInt(n)));
const u256 = (n: bigint): xdr.ScVal => nativeToScVal(n, { type: "u256" });
const i128 = (n: bigint): xdr.ScVal => nativeToScVal(n, { type: "i128" });
const bytes = (b: Uint8Array): xdr.ScVal =>
  xdr.ScVal.scvBytes(b as unknown as Parameters<typeof xdr.ScVal.scvBytes>[0]);

const DAY = 86_400n;
// The native asset contract creates a missing account with a transfer of at least its minimum
// balance, two base reserves.
const NEW_ACCOUNT_MIN = 10_000_000n;
const randomFill = (length: number): Uint8Array => crypto.getRandomValues(new Uint8Array(length));
const REFUND_DELAY = DAY;
const VK = parseVerifyingKey(JSON.parse(new TextDecoder().decode(TRAPDOOR_VK)));

export function baseAccount(address: string): string {
  return StrKey.isValidMed25519PublicKey(address)
    ? MuxedAccount.fromAddress(address, "0").baseAccount().accountId()
    : address;
}

// The vault's tree as the contract keeps it: the frontier of the last insertion, so that each new
// root costs one hash per level.
class Frontier {
  leafCount = 0;
  readonly #filled: bigint[] = [];
  #root = EMPTY_ROOT;

  append(leaves: readonly bigint[]): void {
    for (const leaf of leaves) {
      let node = leaf;
      let index = this.leafCount;
      for (let level = 0; level < LEVELS; level++) {
        if (index % 2 === 0) {
          this.#filled[level] = node;
          node = compress(node, ZEROS[level] as bigint);
        } else {
          node = compress(this.#filled[level] as bigint, node);
        }
        index = Math.floor(index / 2);
      }
      this.#root = node;
      this.leafCount++;
    }
  }

  root(): bigint {
    return this.#root;
  }
}

export class MockVault {
  readonly address: string;
  readonly token: string;
  readonly networkId: Uint8Array;
  readonly domain: bigint;
  readonly wasmHash: string;
  limits: Limits;
  delaySmall = 3_600n;
  delayLarge = 86_400n;
  depositsPaused = false;
  transfersPaused = false;
  haltedUntil = 0n;
  nextDepositId = 1;
  attestedUpTo = 0;
  tvl = 0n;
  pendingTotal = 0n;
  outflowDay = 0n;
  outflow = 0n;
  exitHead = 1;
  exitTail = 1;
  queuedTotal = 0n;

  readonly tree = new Frontier();
  readonly leaves: {
    index: number;
    cm: bigint;
    ciphertext: Uint8Array;
    ledger: number;
    txHash: string;
  }[] = [];
  readonly roots: bigint[] = Array.from({ length: 256 }, (_, i) => (i === 0 ? EMPTY_ROOT : 0n));
  newest = 0;
  readonly nullifiers = new Map<bigint, { ledger: number; txHash: string }>();
  readonly pending = new Map<number, Pending>();
  readonly resolved: {
    id: number;
    depositor: string;
    amount: bigint;
    createdAt: bigint;
    resolvedAt: bigint;
    outcome: string;
    reason: number | undefined;
    leafIndices: [number, number] | undefined;
  }[] = [];
  readonly dayTotals = new Map<string, bigint>();
  readonly exits = new Map<number, Exit>();
  readonly stranded = new Map<number, Exit>();
  // Exits paid in full by release, and stranded ones whose claims moved all they owed, for the
  // indexer's view of the queue.
  readonly settledExits: Exit[] = [];
  readonly requeuedExits: Exit[] = [];
  readonly events: EmittedEvent[] = [];
  readonly transfers: Transfer[] = [];
  // Accounts that cannot receive a payout, to strand exits in tests.
  readonly unpayable = new Set<string>();
  // The network's accounts, which the world connects to its RPC. A contract always exists.
  accountExists: (account: string) => boolean = () => true;
  createAccount: (account: string) => void = () => {};
  // The issuer keeps the vault itself from paying out.
  vaultCannotPay = false;

  // A simulation runs every check and stops before the first effect.
  dryRun = false;
  // The ledger and transaction the current call runs in.
  ledger = 100;
  timestamp = 1_759_000_000n;
  txHash = "";

  constructor(options: {
    address: string;
    token: string;
    networkId: Uint8Array;
    domain: bigint;
    wasmHash: string;
    limits: Limits;
  }) {
    this.address = options.address;
    this.token = options.token;
    this.networkId = options.networkId;
    this.domain = options.domain;
    this.wasmHash = options.wasmHash;
    this.limits = options.limits;
  }

  #emit(topic: string, fields: [string, xdr.ScVal][]): void {
    this.events.push({ ledger: this.ledger, txHash: this.txHash, topic, fields });
  }

  #halted(): boolean {
    return this.timestamp < this.haltedUntil;
  }

  #binding(ext: ExtData): void {
    if (ext.vault !== this.address) refuse(ERROR.WrongVault);
    if (bytesToHex(ext.networkId) !== bytesToHex(this.networkId)) refuse(ERROR.WrongNetwork);
    if (baseAccount(ext.recipient) === this.address || ext.relayer === this.address) {
      refuse(ERROR.BadParties);
    }
    if (ext.encryptedOutput0.length !== 181 || ext.encryptedOutput1.length !== 181) {
      refuse(ERROR.BadCiphertext);
    }
  }

  #shape(proof: TxProof, ext: ExtData): void {
    if (proof.inputNullifiers.length !== 2 || proof.outputCommitments.length !== 2)
      refuse(ERROR.BadArity);
    for (const x of [
      proof.root,
      proof.publicAmount,
      proof.extDataHash,
      ...proof.inputNullifiers,
      ...proof.outputCommitments,
    ]) {
      if (x >= P) refuse(ERROR.NonCanonical);
    }
    if (proof.inputNullifiers[0] === proof.inputNullifiers[1]) refuse(ERROR.DuplicateNullifier);
    if (proof.outputCommitments[0] === proof.outputCommitments[1])
      refuse(ERROR.DuplicateCommitment);
    if (ext.deadline < this.ledger) refuse(ERROR.Expired);
  }

  #spend(proof: TxProof, ext: ExtData): void {
    for (const nf of proof.inputNullifiers)
      if (this.nullifiers.has(nf)) refuse(ERROR.NullifierSpent);
    if (extDataHash(ext) !== proof.extDataHash) refuse(ERROR.ExtDataHashMismatch);
    if (publicAmount(ext.extAmount, ext.fee) !== proof.publicAmount)
      refuse(ERROR.PublicAmountMismatch);
    const inputs = [
      proof.root,
      proof.publicAmount,
      proof.extDataHash,
      this.domain,
      ...proof.inputNullifiers,
      ...proof.outputCommitments,
    ];
    if (!verifyGroth16(VK, fromHostProof(proof.proof), inputs)) refuse(ERROR.InvalidProof);
  }

  #spendNullifiers(proof: TxProof): void {
    for (const nf of proof.inputNullifiers) {
      this.nullifiers.set(nf, { ledger: this.ledger, txHash: this.txHash });
      this.#emit("new_nullifier", [["nullifier", u256(nf)]]);
    }
  }

  #insertPair(cms: readonly bigint[], ciphertexts: readonly Uint8Array[]): number {
    const index = this.tree.leafCount;
    cms.forEach((cm, i) => {
      this.leaves.push({
        index: index + i,
        cm,
        ciphertext: ciphertexts[i] as Uint8Array,
        ledger: this.ledger,
        txHash: this.txHash,
      });
      this.#emit("new_commitment", [
        ["index", u64(index + i)],
        ["commitment", u256(cm)],
        ["encrypted_output", bytes(ciphertexts[i] as Uint8Array)],
      ]);
    });
    this.tree.append(cms);
    this.newest = (this.newest + 1) % 256;
    this.roots[this.newest] = this.tree.root();
    return index;
  }

  #pay(to: string, amount: bigint): void {
    if (amount === 0n) return;
    const account = baseAccount(to);
    if (!this.accountExists(account)) this.createAccount(account);
    this.transfers.push({ from: this.address, to: account, amount });
  }

  // What the asset contract takes: a transfer to an account that can hold the asset, or one that
  // creates a missing account with at least its minimum balance. A relayer is paid fees, which
  // are too small to create it, so it must exist.
  #receives(to: string, amount: bigint): boolean {
    const account = baseAccount(to);
    if (this.unpayable.has(account)) return false;
    return (
      this.accountExists(account) || (!StrKey.isValidContract(to) && amount >= NEW_ACCOUNT_MIN)
    );
  }

  shield(proof: TxProof, ext: ExtData, depositor: string): bigint {
    if (this.#halted()) refuse(ERROR.Halted);
    if (this.depositsPaused) refuse(ERROR.DepositsPaused);
    if (proof.root !== EMPTY_ROOT) refuse(ERROR.NonEmptyRoot);
    if (ext.extAmount <= 0n) refuse(ERROR.BadAmount);
    if (ext.fee !== 0n) refuse(ERROR.BadFee);
    if (ext.recipient !== depositor || ext.relayer !== depositor) refuse(ERROR.BadParties);
    this.#binding(ext);
    const amount = ext.extAmount;
    if (amount < this.limits.minDeposit) refuse(ERROR.DepositTooSmall);
    if (amount > this.limits.maxDeposit) refuse(ERROR.DepositTooLarge);
    const day = this.timestamp / DAY;
    const key = `${depositor}/${day}`;
    const dayTotal = (this.dayTotals.get(key) ?? 0n) + amount;
    if (dayTotal > this.limits.maxDailyPerDepositor) refuse(ERROR.DepositorDailyLimit);
    if (this.tvl + amount > this.limits.tvlCap) refuse(ERROR.TvlCapExceeded);
    this.#shape(proof, ext);
    this.#spend(proof, ext);
    if (this.dryRun) return BigInt(this.nextDepositId);
    this.#spendNullifiers(proof);
    const id = this.nextDepositId++;
    this.tvl += amount;
    this.pendingTotal += amount;
    this.pending.set(id, {
      depositor,
      amount,
      commitments: [proof.outputCommitments[0], proof.outputCommitments[1]],
      ciphertexts: [ext.encryptedOutput0, ext.encryptedOutput1],
      createdAt: this.timestamp,
      delay: this.#delay(amount),
      flag: undefined,
      flaggedAt: 0n,
    });
    this.dayTotals.set(key, dayTotal);
    this.#emit("deposit_pending", [
      ["id", u64(id)],
      ["depositor", new Address(depositor).toScVal()],
      ["amount", i128(amount)],
      ["commitment0", u256(proof.outputCommitments[0])],
      ["commitment1", u256(proof.outputCommitments[1])],
      ["created_at", u64(this.timestamp)],
    ]);
    this.transfers.push({ from: depositor, to: this.address, amount });
    return BigInt(id);
  }

  #delay(amount: bigint): bigint {
    return amount >= this.limits.largeDepositThreshold ? this.delayLarge : this.delaySmall;
  }

  transact(proof: TxProof, ext: ExtData, submitter: string): void {
    void submitter;
    if (this.#halted()) refuse(ERROR.Halted);
    if (ext.extAmount > 0n) refuse(ERROR.BadAmount);
    if (ext.extAmount === 0n && this.transfersPaused) refuse(ERROR.TransfersPaused);
    if (ext.fee < 0n || ext.fee > this.limits.maxFee) refuse(ERROR.BadFee);
    if (ext.extAmount === 0n && ext.recipient !== ext.relayer) refuse(ERROR.BadParties);
    this.#binding(ext);
    const payout = -ext.extAmount;
    const outflow = payout + ext.fee;
    if (outflow > this.limits.maxDailyOutflow) refuse(ERROR.ExceedsDailyOutflow);
    if (outflow > this.tvl - this.pendingTotal - this.queuedTotal) {
      refuse(ERROR.ExceedsAdmittedValue);
    }
    // A party paid by the exit must be able to receive now, whether it is paid at once or queued;
    // only the recipient of a payout large enough to create its account may be missing.
    if (
      (payout > 0n && !this.#receives(ext.recipient, payout)) ||
      (ext.fee > 0n && !this.#receives(ext.relayer, 0n))
    ) {
      refuse(ERROR.CannotReceive);
    }
    this.#shape(proof, ext);
    if (proof.root === 0n || !this.roots.includes(proof.root)) refuse(ERROR.UnknownRoot);
    this.#spend(proof, ext);
    if (this.dryRun) return;
    this.#spendNullifiers(proof);
    this.#insertPair(proof.outputCommitments, [ext.encryptedOutput0, ext.encryptedOutput1]);
    const day = this.timestamp / DAY;
    const usedToday = this.outflowDay === day ? this.outflow : 0n;
    const fits =
      this.exitHead === this.exitTail && usedToday + outflow <= this.limits.maxDailyOutflow;
    if (outflow > 0n && !fits) {
      const id = this.exitTail++;
      this.queuedTotal += outflow;
      this.exits.set(id, {
        id,
        payout,
        fee: ext.fee,
        queuedPayout: payout,
        queuedFee: ext.fee,
        movedPayout: 0n,
        movedFee: 0n,
        recipient: ext.recipient,
        relayer: ext.relayer,
        queuedAt: this.timestamp,
        txHash: this.txHash,
        ledger: this.ledger,
        requeuedFrom: undefined,
        requeuedTo: [],
      });
      this.#emit("exit_queued", [
        ["id", u64(id)],
        ["ext_amount", i128(ext.extAmount)],
        ["fee", i128(ext.fee)],
        ["recipient", new Address(ext.recipient).toScVal()],
        ["relayer", new Address(ext.relayer).toScVal()],
      ]);
      return;
    }
    this.tvl -= outflow;
    this.outflowDay = day;
    this.outflow = usedToday + outflow;
    this.#settled(ext.extAmount, ext.fee, ext.recipient, ext.relayer, undefined);
    this.#pay(ext.recipient, payout);
    this.#pay(ext.relayer, ext.fee);
  }

  #settled(
    extAmount: bigint,
    fee: bigint,
    recipient: string,
    relayer: string,
    exitId: number | undefined,
  ): void {
    this.#emit("settled", [
      ["ext_amount", i128(extAmount)],
      ["fee", i128(fee)],
      ["recipient", new Address(recipient).toScVal()],
      ["relayer", new Address(relayer).toScVal()],
      ["exit_id", exitId === undefined ? xdr.ScVal.scvVoid() : u64(exitId)],
    ]);
  }

  // Pays one part of an exit unless the asset contract would refuse it, and returns what it paid.
  #tryPay(to: string, amount: bigint): bigint {
    if (amount === 0n || !this.#receives(to, amount)) return 0n;
    this.#pay(to, amount);
    return amount;
  }

  // Pays queued exits from the head until today's window is full: of an exit that does not fit, the
  // part that does, payout first, and the rest stays at the head. An exit with a part the asset
  // contract refuses is set aside as stranded with everything it still owes.
  release(max: number): number {
    if (this.#halted()) refuse(ERROR.Halted);
    const day = this.timestamp / DAY;
    let today = this.outflowDay === day ? this.outflow : 0n;
    // A vault that cannot pay stops with the queue as it is, and fails if it would pay nothing.
    const due = this.exitHead < this.exitTail && today < this.limits.maxDailyOutflow;
    if (due && this.vaultCannotPay) refuse(ERROR.VaultCannotPay);
    if (this.dryRun) return 0;
    let count = 0;
    while (count < max && this.exitHead < this.exitTail) {
      const room = this.limits.maxDailyOutflow - today;
      if (room === 0n) break;
      const id = this.exitHead;
      const exit = this.exits.get(id) as Exit;
      const payout = exit.payout < room ? exit.payout : room;
      // No first part below its minimum balance goes to an account the payout creates; the exit
      // waits for the next window.
      const missing = !this.accountExists(baseAccount(exit.recipient));
      if (missing && payout < NEW_ACCOUNT_MIN && exit.payout >= NEW_ACCOUNT_MIN) break;
      count++;
      const fee = exit.fee < room - payout ? exit.fee : room - payout;
      const payoutPaid = this.#tryPay(exit.recipient, payout);
      const feePaid = this.#tryPay(exit.relayer, fee);
      const paid = payoutPaid + feePaid;
      today += paid;
      this.tvl -= paid;
      this.queuedTotal -= paid;
      const left = { ...exit, payout: exit.payout - payoutPaid, fee: exit.fee - feePaid };
      if (payoutPaid < payout || feePaid < fee) {
        this.exits.delete(id);
        this.exitHead++;
        this.stranded.set(id, left);
        this.#emit("exit_stranded", [
          ["id", u64(id)],
          ["payout", i128(left.payout)],
          ["fee", i128(left.fee)],
        ]);
      } else if (left.payout === 0n && left.fee === 0n) {
        this.exits.delete(id);
        this.exitHead++;
        this.settledExits.push(left);
        this.#settled(-payoutPaid, feePaid, exit.recipient, exit.relayer, id);
      } else {
        this.exits.set(id, left);
        this.#exitPaid(id, payoutPaid, feePaid, left);
      }
    }
    if (count > 0) {
      this.outflowDay = day;
      this.outflow = today;
    }
    return count;
  }

  #exitPaid(id: number, payoutPaid: bigint, feePaid: bigint, left: Exit): void {
    this.#emit("exit_paid", [
      ["id", u64(id)],
      ["payout_paid", i128(payoutPaid)],
      ["fee_paid", i128(feePaid)],
      ["payout_left", i128(left.payout)],
      ["fee_left", i128(left.fee)],
    ]);
  }

  // Moves the parts of a stranded exit whose party can receive now to the tail of the queue as a
  // new exit and returns its ID. The value stays owed, so queuedTotal and tvl do not change.
  claim(id: number): bigint {
    if (this.#halted()) refuse(ERROR.Halted);
    const exit = this.stranded.get(id) ?? refuse(ERROR.NotStranded);
    // Judged as transact judges the parties.
    const payout =
      exit.payout > 0n && this.#receives(exit.recipient, exit.payout) ? exit.payout : 0n;
    const fee = exit.fee > 0n && this.#receives(exit.relayer, 0n) ? exit.fee : 0n;
    if (payout === 0n && fee === 0n) refuse(ERROR.NothingClaimable);
    if (this.dryRun) return BigInt(this.exitTail);
    const newId = this.exitTail++;
    const left = {
      ...exit,
      payout: exit.payout - payout,
      fee: exit.fee - fee,
      movedPayout: exit.movedPayout + payout,
      movedFee: exit.movedFee + fee,
      requeuedTo: [...exit.requeuedTo, newId],
    };
    if (left.payout === 0n && left.fee === 0n) {
      this.stranded.delete(id);
      this.requeuedExits.push(left);
    } else {
      this.stranded.set(id, left);
    }
    this.exits.set(newId, {
      ...exit,
      id: newId,
      payout,
      fee,
      queuedPayout: payout,
      queuedFee: fee,
      movedPayout: 0n,
      movedFee: 0n,
      queuedAt: this.timestamp,
      txHash: this.txHash,
      ledger: this.ledger,
      requeuedFrom: id,
      requeuedTo: [],
    });
    this.#emit("exit_requeued", [
      ["id", u64(id)],
      ["new_id", u64(newId)],
      ["payout", i128(payout)],
      ["fee", i128(fee)],
    ]);
    return BigInt(newId);
  }

  // Other users' activity: pairs of random commitments, each pair its own insertion.
  insertFiller(pairs: number): void {
    for (let i = 0; i < pairs; i++) {
      const cms = [0, 1].map(() => BigInt("0x" + bytesToHex(randomFill(32))) % P);
      this.#insertPair(cms, [randomFill(181), randomFill(181)]);
    }
  }

  attest(upTo: number): void {
    this.attestedUpTo = upTo;
    this.#emit("attested", [["up_to", u64(upTo)]]);
  }

  flag(id: number, reason: number): void {
    const deposit = this.pending.get(id) ?? refuse(ERROR.UnknownDeposit);
    if (deposit.flag === undefined) deposit.flaggedAt = this.timestamp;
    deposit.flag = reason;
    this.#emit("deposit_flagged", [
      ["id", u64(id)],
      ["reason", xdr.ScVal.scvU32(reason)],
    ]);
  }

  admit(ids: readonly number[]): number[] {
    const admitted: number[] = [];
    for (const id of ids) {
      const deposit = this.pending.get(id);
      if (deposit === undefined) continue;
      const delay =
        deposit.delay > this.#delay(deposit.amount) ? deposit.delay : this.#delay(deposit.amount);
      if (
        deposit.flag !== undefined ||
        id > this.attestedUpTo ||
        this.timestamp < deposit.createdAt + delay
      )
        continue;
      const index = this.#insertPair(deposit.commitments, deposit.ciphertexts);
      this.#emit("deposit_admitted", [
        ["id", u64(id)],
        ["leaf_index0", u64(index)],
        ["leaf_index1", u64(index + 1)],
      ]);
      this.pending.delete(id);
      this.pendingTotal -= deposit.amount;
      this.resolved.push({
        id,
        depositor: deposit.depositor,
        amount: deposit.amount,
        createdAt: deposit.createdAt,
        resolvedAt: this.timestamp,
        outcome: "admitted",
        reason: undefined,
        leafIndices: [index, index + 1],
      });
      admitted.push(id);
    }
    return admitted;
  }

  #release(id: number, deposit: Pending, reason: number, outcome: string): void {
    this.pending.delete(id);
    this.tvl -= deposit.amount;
    this.pendingTotal -= deposit.amount;
    this.#emit("deposit_refunded", [
      ["id", u64(id)],
      ["reason", xdr.ScVal.scvU32(reason)],
    ]);
    this.resolved.push({
      id,
      depositor: deposit.depositor,
      amount: deposit.amount,
      createdAt: deposit.createdAt,
      resolvedAt: this.timestamp,
      outcome,
      reason,
      leafIndices: undefined,
    });
    this.transfers.push({ from: this.address, to: deposit.depositor, amount: deposit.amount });
  }

  cancel(id: number, caller: string): void {
    const deposit = this.pending.get(id) ?? refuse(ERROR.UnknownDeposit);
    if (deposit.depositor !== caller) throw new Error("auth: only the depositor cancels");
    if (this.dryRun) return;
    this.#release(id, deposit, 0, "cancelled");
  }

  refund(id: number): void {
    const deposit = this.pending.get(id) ?? refuse(ERROR.UnknownDeposit);
    const reason = deposit.flag ?? refuse(ERROR.NotFlagged);
    if (this.timestamp < deposit.flaggedAt + REFUND_DELAY) refuse(ERROR.RefundTooEarly);
    if (this.dryRun) return;
    this.#release(id, deposit, reason, "refunded");
  }

  // The instance storage the vault keeps under DataKey::Config, Limits and Status.
  instanceStorage(): xdr.ScMapEntry[] {
    const key = (name: string): xdr.ScVal => xdr.ScVal.scvVec([xdr.ScVal.scvSymbol(name)]);
    const status: [string, xdr.ScVal][] = [
      ["deposits_paused", xdr.ScVal.scvBool(this.depositsPaused)],
      ["transfers_paused", xdr.ScVal.scvBool(this.transfersPaused)],
      ["halted_until", u64(this.haltedUntil)],
      ["next_halt_at", u64(0)],
      ["next_deposit_id", u64(this.nextDepositId)],
      ["attested_up_to", u64(this.attestedUpTo)],
      ["tvl", i128(this.tvl)],
      ["pending_total", i128(this.pendingTotal)],
      ["outflow_day", u64(this.outflowDay)],
      ["outflow", i128(this.outflow)],
      ["exit_head", u64(this.exitHead)],
      ["exit_tail", u64(this.exitTail)],
      ["queued_total", i128(this.queuedTotal)],
    ];
    return [
      new xdr.ScMapEntry({
        key: key("Config"),
        val: map([
          ["token", new Address(this.token).toScVal()],
          ["domain", u256(this.domain)],
          ["guardian", new Address(this.token).toScVal()],
          ["asp", new Address(this.token).toScVal()],
          ["delay_small", u64(this.delaySmall)],
          ["delay_large", u64(this.delayLarge)],
        ]),
      }),
      new xdr.ScMapEntry({
        key: key("Limits"),
        val: map([
          ["min_deposit", i128(this.limits.minDeposit)],
          ["max_deposit", i128(this.limits.maxDeposit)],
          ["max_daily_per_depositor", i128(this.limits.maxDailyPerDepositor)],
          ["tvl_cap", i128(this.limits.tvlCap)],
          ["max_daily_outflow", i128(this.limits.maxDailyOutflow)],
          ["max_fee", i128(this.limits.maxFee)],
          ["large_deposit_threshold", i128(this.limits.largeDepositThreshold)],
        ]),
      }),
      new xdr.ScMapEntry({ key: key("Status"), val: map(status) }),
    ];
  }

  rootRing(): xdr.ScVal {
    return map([
      ["roots", xdr.ScVal.scvVec(this.roots.map(u256))],
      ["newest", xdr.ScVal.scvU32(this.newest)],
    ]);
  }

  pendingEntry(id: number): xdr.ScVal | undefined {
    const d = this.pending.get(id);
    if (d === undefined) return undefined;
    return map([
      ["depositor", new Address(d.depositor).toScVal()],
      ["amount", i128(d.amount)],
      ["commitment0", u256(d.commitments[0])],
      ["commitment1", u256(d.commitments[1])],
      ["encrypted_output0", bytes(d.ciphertexts[0])],
      ["encrypted_output1", bytes(d.ciphertexts[1])],
      ["created_at", u64(d.createdAt)],
      ["delay", u64(d.delay)],
      ["flag", d.flag === undefined ? xdr.ScVal.scvVoid() : xdr.ScVal.scvU32(d.flag)],
      ["flagged_at", u64(d.flaggedAt)],
    ]);
  }
}

export const hex = bytesToHex;
export const unhex = hexToBytes;
