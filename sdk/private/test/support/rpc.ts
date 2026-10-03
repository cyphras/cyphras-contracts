// A Soroban RPC over the vault model, answering the JSON-RPC methods the SDK uses with the XDR a
// real RPC returns: ledger entries, simulations with authorization entries, submissions checked
// for signature and sequence, transaction meta with events, and contract events.
import {
  Address,
  FeeBumpTransaction,
  Keypair,
  SorobanDataBuilder,
  StrKey,
  type Transaction,
  TransactionBuilder,
  scValToBigInt,
  xdr,
} from "@stellar/stellar-base";
import { bytesToHex, hexToBytes } from "../../src/bytes.ts";
import { type ExtData, type TxProof, type HostProof } from "../../src/extdata.ts";
import { type EmittedEvent, MockVault, VaultError, map } from "./vault.ts";

interface TxRecord {
  status: "SUCCESS" | "FAILED";
  ledger: number;
  returnValue: xdr.ScVal;
  events: EmittedEvent[];
}

// Decodes the vault's contracttype arguments back into SDK values.
function fields(value: xdr.ScVal): Map<string, xdr.ScVal> {
  return new Map((value.map() ?? []).map((e) => [e.key().sym().toString(), e.val()]));
}

const get = (m: Map<string, xdr.ScVal>, k: string): xdr.ScVal => {
  const v = m.get(k);
  if (v === undefined) throw new Error(`missing ${k}`);
  return v;
};

export function decodeTxProof(value: xdr.ScVal): TxProof {
  const f = fields(value);
  const proof = fields(get(f, "proof"));
  const b = (k: string): Uint8Array => Uint8Array.from(get(proof, k).bytes());
  const vec = (k: string): [bigint, bigint] => {
    const items = (get(f, k).vec() ?? []).map((v) => scValToBigInt(v));
    return [items[0] as bigint, items[1] as bigint];
  };
  return {
    proof: { a: b("a"), b: b("b"), c: b("c") } as HostProof,
    root: scValToBigInt(get(f, "root")),
    publicAmount: scValToBigInt(get(f, "public_amount")),
    extDataHash: scValToBigInt(get(f, "ext_data_hash")),
    inputNullifiers: vec("input_nullifiers"),
    outputCommitments: vec("output_commitments"),
  };
}

export function decodeExtData(value: xdr.ScVal): ExtData {
  const f = fields(value);
  const address = (k: string): string => Address.fromScAddress(get(f, k).address()).toString();
  return {
    vault: address("vault"),
    networkId: Uint8Array.from(get(f, "network_id").bytes()),
    deadline: get(f, "deadline").u32(),
    extAmount: scValToBigInt(get(f, "ext_amount")),
    fee: scValToBigInt(get(f, "fee")),
    recipient: address("recipient"),
    relayer: address("relayer"),
    encryptedOutput0: Uint8Array.from(get(f, "encrypted_output0").bytes()),
    encryptedOutput1: Uint8Array.from(get(f, "encrypted_output1").bytes()),
  };
}

const addressOf = (v: xdr.ScVal | undefined): string =>
  Address.fromScAddress((v as xdr.ScVal).address()).toString();

export class RpcFailure extends Error {
  readonly code: number;
  constructor(code: number, message: string) {
    super(message);
    this.code = code;
  }
}

export interface Account {
  readonly keypair: Keypair;
  sequence: bigint;
  createdLedger: number;
}

export class MockRpc {
  readonly vault: MockVault;
  readonly passphrase: string;
  readonly accounts = new Map<string, Account>();
  // Trustlines of an issued pool asset, by account.
  readonly trustlines = new Map<string, { authorized: boolean; limit: bigint; balance: bigint }>();
  readonly contracts = new Set<string>();
  readonly records = new Map<string, TxRecord>();
  oldestLedger = 1;
  calls: string[] = [];
  // The fee of every transaction sent, in stroops.
  sentFees: bigint[] = [];
  // Test hooks: extra authorization the simulation asks for, and a send status to return once.
  injectAuth: xdr.SorobanAuthorizationEntry | undefined;
  sendOnce: string | undefined;

  constructor(vault: MockVault, passphrase: string) {
    this.vault = vault;
    this.passphrase = passphrase;
  }

  // An account the native asset contract created with a payment, whose key no test holds.
  createAccount(publicKey: string): void {
    this.account(Keypair.fromPublicKey(publicKey));
  }

  account(keypair: Keypair): Account {
    const account = {
      keypair,
      sequence: BigInt(this.vault.ledger) << 32n,
      createdLedger: this.vault.ledger,
    };
    this.accounts.set(keypair.publicKey(), account);
    return account;
  }

  // Runs one vault call as its own transaction in a new ledger, and keeps its result for
  // getTransaction as a real RPC would for a transaction it saw.
  run<T>(txHash: string, fn: () => T): T {
    this.vault.ledger++;
    this.vault.txHash = txHash;
    const before = this.vault.events.length;
    try {
      const result = fn();
      this.records.set(txHash, {
        status: "SUCCESS",
        ledger: this.vault.ledger,
        returnValue:
          typeof result === "bigint"
            ? xdr.ScVal.scvU64(new xdr.Uint64(result))
            : xdr.ScVal.scvVoid(),
        events: this.vault.events.slice(before),
      });
      return result;
    } catch (err) {
      this.records.set(txHash, {
        status: "FAILED",
        ledger: this.vault.ledger,
        returnValue: xdr.ScVal.scvVoid(),
        events: [],
      });
      throw err;
    }
  }

  #invoke(tx: Transaction): { fn: string; args: xdr.ScVal[]; source: string } {
    const op = tx.operations[0];
    if (op === undefined || op.type !== "invokeHostFunction")
      throw new Error("not a contract call");
    const call = op.func.invokeContract();
    const contract = Address.fromScAddress(call.contractAddress()).toString();
    if (contract !== this.vault.address) throw new Error("a call to another contract");
    return { fn: call.functionName().toString(), args: call.args(), source: tx.source };
  }

  #execute(fn: string, args: xdr.ScVal[], source: string): xdr.ScVal {
    const v = this.vault;
    switch (fn) {
      case "shield":
        return xdr.ScVal.scvU64(
          new xdr.Uint64(
            v.shield(
              decodeTxProof(args[0] as xdr.ScVal),
              decodeExtData(args[1] as xdr.ScVal),
              addressOf(args[2]),
            ),
          ),
        );
      case "transact":
        v.transact(
          decodeTxProof(args[0] as xdr.ScVal),
          decodeExtData(args[1] as xdr.ScVal),
          addressOf(args[2]),
        );
        return xdr.ScVal.scvVoid();
      case "cancel":
        v.cancel(Number(scValToBigInt(args[0] as xdr.ScVal)), source);
        return xdr.ScVal.scvVoid();
      case "refund":
        v.refund(Number(scValToBigInt(args[0] as xdr.ScVal)));
        return xdr.ScVal.scvVoid();
      case "release":
        return xdr.ScVal.scvU32(v.release((args[0] as xdr.ScVal).u32()));
      case "claim":
        return xdr.ScVal.scvU64(
          new xdr.Uint64(v.claim(Number(scValToBigInt(args[0] as xdr.ScVal)))),
        );
      default:
        throw new Error(`unknown function ${fn}`);
    }
  }

  // The authorization a call needs from its source: the call itself, and for a shield the
  // token transfer from the depositor.
  #auth(fn: string, args: xdr.ScVal[], tx: Transaction): xdr.SorobanAuthorizationEntry[] {
    if (!["shield", "transact", "cancel"].includes(fn)) return [];
    const invoke = (
      contract: string,
      name: string,
      a: xdr.ScVal[],
    ): xdr.SorobanAuthorizedFunction =>
      xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(
        new xdr.InvokeContractArgs({
          contractAddress: new Address(contract).toScAddress(),
          functionName: name,
          args: a,
        }),
      );
    const subs: xdr.SorobanAuthorizedInvocation[] = [];
    if (fn === "shield") {
      const amount = decodeExtData(args[1] as xdr.ScVal).extAmount;
      subs.push(
        new xdr.SorobanAuthorizedInvocation({
          function: invoke(this.vault.token, "transfer", [
            new Address(tx.source).toScVal(),
            new Address(this.vault.address).toScVal(),
            xdr.ScVal.scvI128(
              new xdr.Int128Parts({
                hi: xdr.Int64.fromString("0"),
                lo: xdr.Uint64.fromString(amount.toString()),
              }),
            ),
          ]),
          subInvocations: [],
        }),
      );
    }
    const entries = [
      new xdr.SorobanAuthorizationEntry({
        credentials: xdr.SorobanCredentials.sorobanCredentialsSourceAccount(),
        rootInvocation: new xdr.SorobanAuthorizedInvocation({
          function: invoke(this.vault.address, fn, args),
          subInvocations: subs,
        }),
      }),
    ];
    if (this.injectAuth !== undefined) entries.push(this.injectAuth);
    return entries;
  }

  #entries(keys: string[]): unknown[] {
    const out: unknown[] = [];
    for (const id of keys) {
      const key = xdr.LedgerKey.fromXDR(id, "base64");
      const data = this.#entry(key);
      if (data !== undefined) {
        out.push({
          key: id,
          xdr: data.toXDR("base64"),
          lastModifiedLedgerSeq: this.vault.ledger,
          liveUntilLedgerSeq: this.vault.ledger + 100_000,
        });
      }
    }
    return out;
  }

  #entry(key: xdr.LedgerKey): xdr.LedgerEntryData | undefined {
    if (key.switch().name === "account") {
      const id = StrKey.encodeEd25519PublicKey(key.account().accountId().ed25519());
      const account = this.accounts.get(id);
      if (account === undefined) return undefined;
      return xdr.LedgerEntryData.account(
        new xdr.AccountEntry({
          accountId: account.keypair.xdrAccountId(),
          balance: xdr.Int64.fromString("100000000000"),
          seqNum: xdr.Int64.fromString(account.sequence.toString()),
          numSubEntries: 0,
          inflationDest: null,
          flags: 0,
          homeDomain: "",
          thresholds: Buffer.from([1, 0, 0, 0]),
          signers: [],
          ext: new xdr.AccountEntryExt(0),
        }),
      );
    }
    if (key.switch().name === "trustline") {
      const id = StrKey.encodeEd25519PublicKey(key.trustLine().accountId().ed25519());
      const line = this.trustlines.get(id);
      if (line === undefined) return undefined;
      return xdr.LedgerEntryData.trustline(
        new xdr.TrustLineEntry({
          accountId: key.trustLine().accountId(),
          asset: key.trustLine().asset(),
          balance: xdr.Int64.fromString(line.balance.toString()),
          limit: xdr.Int64.fromString(line.limit.toString()),
          flags: line.authorized ? 1 : 0,
          ext: new xdr.TrustLineEntryExt(0),
        }),
      );
    }
    if (key.switch().name !== "contractData") return undefined;
    const cd = key.contractData();
    const contract = Address.fromScAddress(cd.contract()).toString();
    const entry = (val: xdr.ScVal): xdr.LedgerEntryData =>
      xdr.LedgerEntryData.contractData(
        new xdr.ContractDataEntry({
          ext: new xdr.ExtensionPoint(0),
          contract: cd.contract(),
          key: cd.key(),
          durability: cd.durability(),
          val,
        }),
      );
    const k = cd.key();
    if (k.switch().name === "scvLedgerKeyContractInstance") {
      if (contract === this.vault.address) {
        return entry(
          xdr.ScVal.scvContractInstance(
            new xdr.ScContractInstance({
              executable: xdr.ContractExecutable.contractExecutableWasm(
                Buffer.from(hexToBytes(this.vault.wasmHash)),
              ),
              storage: this.vault.instanceStorage(),
            }),
          ),
        );
      }
      if (this.contracts.has(contract)) {
        return entry(
          xdr.ScVal.scvContractInstance(
            new xdr.ScContractInstance({
              executable: xdr.ContractExecutable.contractExecutableStellarAsset(),
              storage: null,
            }),
          ),
        );
      }
      return undefined;
    }
    if (contract !== this.vault.address || k.switch().name !== "scvVec") return undefined;
    const [variant, ...rest] = k.vec() ?? [];
    switch (variant?.sym().toString()) {
      case "Roots":
        return entry(this.vault.rootRing());
      case "NextLeaf":
        return entry(xdr.ScVal.scvU64(new xdr.Uint64(BigInt(this.vault.tree.leafCount))));
      case "Pending": {
        const val = this.vault.pendingEntry(Number(scValToBigInt(rest[0] as xdr.ScVal)));
        return val === undefined ? undefined : entry(val);
      }
      case "DepositorDay": {
        const total = this.vault.dayTotals.get(
          `${addressOf(rest[0])}/${scValToBigInt(rest[1] as xdr.ScVal)}`,
        );
        return total === undefined
          ? undefined
          : entry(
              xdr.ScVal.scvI128(
                new xdr.Int128Parts({
                  hi: xdr.Int64.fromString("0"),
                  lo: xdr.Uint64.fromString(total.toString()),
                }),
              ),
            );
      }
      default:
        return undefined;
    }
  }

  #parse(envelope: string): Transaction {
    const tx = TransactionBuilder.fromXDR(envelope, this.passphrase);
    if (tx instanceof FeeBumpTransaction) throw new Error("fee bumps are not expected");
    return tx;
  }

  #meta(record: TxRecord): string {
    const events = record.events.map(
      (e) =>
        new xdr.ContractEvent({
          ext: new xdr.ExtensionPoint(0),
          contractId: StrKey.decodeContract(this.vault.address) as unknown as xdr.ContractId,
          type: xdr.ContractEventType.contract(),
          body: new xdr.ContractEventBody(
            0,
            new xdr.ContractEventV0({
              topics: [xdr.ScVal.scvSymbol(e.topic)],
              data: map(e.fields),
            }),
          ),
        }),
    );
    return new xdr.TransactionMeta(
      4,
      new xdr.TransactionMetaV4({
        ext: new xdr.ExtensionPoint(0),
        txChangesBefore: [],
        operations: [
          new xdr.OperationMetaV2({ ext: new xdr.ExtensionPoint(0), changes: [], events }),
        ],
        txChangesAfter: [],
        sorobanMeta: new xdr.SorobanTransactionMetaV2({
          ext: new xdr.SorobanTransactionMetaExt(0),
          returnValue: record.returnValue,
        }),
        events: [],
        diagnosticEvents: [],
      }),
    ).toXDR("base64");
  }

  handle(method: string, params: Record<string, unknown>): unknown {
    this.calls.push(method);
    switch (method) {
      case "getNetwork":
        return { passphrase: this.passphrase, protocolVersion: 23 };
      case "getLatestLedger":
        return { id: "x", protocolVersion: 23, sequence: this.vault.ledger };
      case "getFeeStats":
        return {
          sorobanInclusionFee: { p90: "150" },
          inclusionFee: { p90: "100" },
          latestLedger: this.vault.ledger,
        };
      case "getLedgerEntries":
        return {
          entries: this.#entries(params["keys"] as string[]),
          latestLedger: this.vault.ledger,
        };
      case "simulateTransaction": {
        const tx = this.#parse(params["transaction"] as string);
        const { fn, args, source } = this.#invoke(tx);
        this.vault.dryRun = true;
        try {
          const result = this.#execute(fn, args, source);
          return {
            transactionData: new SorobanDataBuilder().setResourceFee(1000).build().toXDR("base64"),
            minResourceFee: "1000",
            results: [
              {
                auth: this.#auth(fn, args, tx).map((a) => a.toXDR("base64")),
                xdr: result.toXDR("base64"),
              },
            ],
            latestLedger: this.vault.ledger,
          };
        } catch (err) {
          const message = err instanceof VaultError ? `HostError: ${err.message}` : String(err);
          return { error: message, latestLedger: this.vault.ledger };
        } finally {
          this.vault.dryRun = false;
        }
      }
      case "sendTransaction": {
        const tx = this.#parse(params["transaction"] as string);
        const hash = bytesToHex(Uint8Array.from(tx.hash()));
        this.sentFees.push(BigInt(tx.fee));
        if (this.sendOnce !== undefined) {
          const status = this.sendOnce;
          this.sendOnce = undefined;
          return { status, hash, latestLedger: this.vault.ledger };
        }
        if (this.records.has(hash))
          return { status: "DUPLICATE", hash, latestLedger: this.vault.ledger };
        const account = this.accounts.get(tx.source);
        const signed = tx.signatures.some((s) => account?.keypair.verify(tx.hash(), s.signature()));
        if (account === undefined || !signed || BigInt(tx.sequence) !== account.sequence + 1n) {
          return { status: "ERROR", hash, latestLedger: this.vault.ledger };
        }
        account.sequence++;
        const { fn, args, source } = this.#invoke(tx);
        const before = this.vault.events.length;
        try {
          const returnValue = this.run(hash, () => this.#execute(fn, args, source));
          this.records.set(hash, {
            status: "SUCCESS",
            ledger: this.vault.ledger,
            returnValue,
            events: this.vault.events.slice(before),
          });
        } catch {
          // run() has recorded the failure
        }
        return { status: "PENDING", hash, latestLedger: this.vault.ledger };
      }
      case "getTransaction": {
        const record = this.records.get(params["hash"] as string);
        const base = { latestLedger: this.vault.ledger, oldestLedger: this.oldestLedger };
        if (record === undefined) return { ...base, status: "NOT_FOUND" };
        return {
          ...base,
          status: record.status,
          ledger: record.ledger,
          resultMetaXdr: this.#meta(record),
        };
      }
      case "getEvents":
        return this.#events(params);
      default:
        throw new Error(`unexpected RPC method ${method}`);
    }
  }

  #events(params: Record<string, unknown>): unknown {
    const pagination = (params["pagination"] ?? {}) as { cursor?: string; limit?: number };
    const limit = pagination.limit ?? 100;
    const start = params["startLedger"] as number | undefined;
    if (start !== undefined && start < this.oldestLedger) {
      throw new RpcFailure(-32600, "startLedger must be within the ledger range");
    }
    const all = this.vault.events.map((e, i) => ({
      e,
      id: `${String(e.ledger).padStart(12, "0")}-${String(i).padStart(8, "0")}`,
    }));
    const after = pagination.cursor;
    const selected = all
      .filter(({ e, id }) => (after === undefined ? e.ledger >= (start ?? 0) : id > after))
      .slice(0, limit);
    return {
      events: selected.map(({ e, id }) => ({
        type: "contract",
        ledger: e.ledger,
        ledgerClosedAt: "2026-10-03T00:00:00Z",
        contractId: this.vault.address,
        id,
        pagingToken: id,
        txHash: e.txHash,
        inSuccessfulContractCall: true,
        topic: [xdr.ScVal.scvSymbol(e.topic).toXDR("base64")],
        value: map(e.fields).toXDR("base64"),
      })),
      cursor: selected[selected.length - 1]?.id ?? after ?? "",
      latestLedger: this.vault.ledger,
      oldestLedger: this.oldestLedger,
    };
  }
}

export const keypairFor = (label: string): Keypair =>
  Keypair.fromRawEd25519Seed(
    Buffer.from(
      hexToBytes(bytesToHex(new TextEncoder().encode(label.padEnd(32, "-").slice(0, 32)))),
    ),
  );
