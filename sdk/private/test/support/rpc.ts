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
  // The diagnostic events of a failure, as base64 XDR.
  diagnostics?: string[];
}

// A diagnostic event naming a host error, as the host emits for a failed call.
export function diagnostic(error: xdr.ScError): string {
  return new xdr.DiagnosticEvent({
    inSuccessfulContractCall: false,
    event: new xdr.ContractEvent({
      ext: new xdr.ExtensionPoint(0),
      contractId: null,
      type: xdr.ContractEventType.diagnostic(),
      body: new xdr.ContractEventBody(
        0,
        new xdr.ContractEventV0({
          topics: [xdr.ScVal.scvSymbol("error"), xdr.ScVal.scvError(error)],
          data: xdr.ScVal.scvVoid(),
        }),
      ),
    }),
  }).toXDR("base64");
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

// The ID stellar-rpc gives the `n`-th event, from 1, of a ledger: the TOID of the ledger and its
// transaction, then the event's index.
export const eventId = (ledger: number, n: number): string =>
  `${((BigInt(ledger) << 32n) | (BigInt(n) << 12n)).toString().padStart(19, "0")}-0000000000`;

// The cursor that closes a ledger, which stellar-rpc gives where its scan stopped.
export const ledgerEnd = (ledger: number): string =>
  `${((BigInt(ledger) << 32n) | 0xffffffffn).toString().padStart(19, "0")}-4294967295`;

const ledgerOf = (id: string): number => Number(BigInt(id.split("-")[0] as string) >> 32n);

export class MockRpc {
  readonly vault: MockVault;
  readonly passphrase: string;
  readonly accounts = new Map<string, Account>();
  // Trustlines of an issued pool asset, by account.
  readonly trustlines = new Map<string, { authorized: boolean; limit: bigint; balance: bigint }>();
  readonly contracts = new Set<string>();
  readonly records = new Map<string, TxRecord>();
  oldestLedger = 1;
  // The ledgers one getEvents request scans at most, from its start ledger or its cursor's on, as
  // stellar-rpc bounds a scan.
  scanLedgers = 10_000;
  // The pace at which the ledgers it reports closed, from a fixed moment at ledger 0.
  secondsPerLedger = 5;
  calls: string[] = [];
  // The fee of every transaction sent, in stroops.
  sentFees: bigint[] = [];
  // Test hooks: extra authorization the simulation asks for, and a send status to return once.
  injectAuth: xdr.SorobanAuthorizationEntry | undefined;
  sendOnce: string | undefined;
  // Test hooks: what other transactions do before the next one sent is applied, and whether a
  // call traps, as the host makes it, when it writes an entry that depends on the vault's state
  // and its footprint lacks.
  beforeApply: (() => void) | undefined;
  enforceFootprint = false;
  // Test hooks: how many of the next transactions sent fail on chain on the host's storage, as one
  // whose footprint the chain moved past does, and how many fail in the vault.
  conflictNext = 0;
  failNext = 0;
  // Test hook: failures carry their diagnostic events in their meta, as some RPCs return them.
  diagnosticsInMeta = false;
  // Test hook: the Soroban data simulations report.
  simulated:
    | {
        readOnly: xdr.LedgerKey[];
        readWrite: xdr.LedgerKey[];
        instructions: number;
        readBytes: number;
        writeBytes: number;
        fee: number;
      }
    | undefined;
  // The transactions sent, in order, and how many entries a footprint may declare, write and read
  // from disk.
  sent: Transaction[] = [];
  maxFootprintEntries = 400;
  maxWriteEntries = 200;
  maxDiskReadEntries = 200;

  constructor(vault: MockVault, passphrase: string) {
    this.vault = vault;
    this.passphrase = passphrase;
  }

  // Unix seconds at which a ledger closed, as RPC reports it: on the vault's clock at ledger 100,
  // at the pace the hook sets from there.
  closeTime(ledger: number): number {
    return 1_759_000_000 + this.secondsPerLedger * (ledger - 100);
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

  // The network's Soroban settings: the public network's at ledger 64,754,596, with the limits on
  // a footprint's entries the hooks set.
  #setting(id: xdr.ConfigSettingId): xdr.LedgerEntryData | undefined {
    const int = (n: number): xdr.Int64 => xdr.Int64.fromString(String(n));
    const C = xdr.ConfigSettingEntry;
    const entry = (e: xdr.ConfigSettingEntry): xdr.LedgerEntryData =>
      xdr.LedgerEntryData.configSetting(e);
    switch (id.name) {
      case "configSettingContractComputeV0":
        return entry(
          C.configSettingContractComputeV0(
            new xdr.ConfigSettingContractComputeV0({
              ledgerMaxInstructions: int(600_000_000),
              txMaxInstructions: int(400_000_000),
              feeRatePerInstructionsIncrement: int(7),
              txMemoryLimit: 41_943_040,
            }),
          ),
        );
      case "configSettingContractLedgerCostV0":
        return entry(
          C.configSettingContractLedgerCostV0(
            new xdr.ConfigSettingContractLedgerCostV0({
              ledgerMaxDiskReadEntries: 1_000,
              ledgerMaxDiskReadBytes: 7_000_000,
              ledgerMaxWriteLedgerEntries: 500,
              ledgerMaxWriteBytes: 286_720,
              txMaxDiskReadEntries: this.maxDiskReadEntries,
              txMaxDiskReadBytes: 200_000,
              txMaxWriteLedgerEntries: this.maxWriteEntries,
              txMaxWriteBytes: 132_096,
              feeDiskReadLedgerEntry: int(1_563),
              feeWriteLedgerEntry: int(2_500),
              feeDiskRead1Kb: int(447),
              sorobanStateTargetSizeBytes: int(3_000_000_000),
              rentFee1KbSorobanStateSizeLow: int(-17_000),
              rentFee1KbSorobanStateSizeHigh: int(10_000),
              sorobanStateRentFeeGrowthFactor: 5_000,
            }),
          ),
        );
      case "configSettingContractLedgerCostExtV0":
        return entry(
          C.configSettingContractLedgerCostExtV0(
            new xdr.ConfigSettingContractLedgerCostExtV0({
              txMaxFootprintEntries: this.maxFootprintEntries,
              feeWrite1Kb: int(875),
            }),
          ),
        );
      case "configSettingContractHistoricalDataV0":
        return entry(
          C.configSettingContractHistoricalDataV0(
            new xdr.ConfigSettingContractHistoricalDataV0({ feeHistorical1Kb: int(4_059) }),
          ),
        );
      case "configSettingContractEventsV0":
        return entry(
          C.configSettingContractEventsV0(
            new xdr.ConfigSettingContractEventsV0({
              txMaxContractEventsSizeBytes: 16_384,
              feeContractEvents1Kb: int(5_000),
            }),
          ),
        );
      case "configSettingContractBandwidthV0":
        return entry(
          C.configSettingContractBandwidthV0(
            new xdr.ConfigSettingContractBandwidthV0({
              ledgerMaxTxsSizeBytes: 133_120,
              txMaxSizeBytes: 132_096,
              feeTxSize1Kb: int(406),
            }),
          ),
        );
      case "configSettingStateArchival":
        return entry(
          C.configSettingStateArchival(
            new xdr.StateArchivalSettings({
              maxEntryTtl: 3_110_400,
              minTemporaryTtl: 17_280,
              minPersistentTtl: 2_073_600,
              persistentRentRateDenominator: int(1_215),
              tempRentRateDenominator: int(2_430),
              maxEntriesToArchive: 1_000,
              liveSorobanStateSizeWindowSampleSize: 30,
              liveSorobanStateSizeWindowSamplePeriod: 64,
              evictionScanSize: 100_000,
              startingEvictionScanLevel: 7,
            }),
          ),
        );
      case "configSettingLiveSorobanStateSizeWindow":
        return entry(
          C.configSettingLiveSorobanStateSizeWindow(
            Array.from({ length: 30 }, () => xdr.Uint64.fromString("1664203878")),
          ),
        );
      default:
        return undefined;
    }
  }

  #entry(key: xdr.LedgerKey): xdr.LedgerEntryData | undefined {
    if (key.switch().name === "configSetting") {
      return this.#setting(key.configSetting().configSettingId());
    }
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
      case "Exit": {
        const val = this.vault.exitEntry(Number(scValToBigInt(rest[0] as xdr.ScVal)));
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

  // What a call writes that depends on the vault's state now: the exit at the queue's tail it
  // queues, or the native balances an exit paid at once moves.
  #written(fn: string, args: xdr.ScVal[]): xdr.LedgerKey[] {
    const v = this.vault;
    const exit = (id: number): xdr.LedgerKey =>
      xdr.LedgerKey.contractData(
        new xdr.LedgerKeyContractData({
          contract: new Address(v.address).toScAddress(),
          key: xdr.ScVal.scvVec([
            xdr.ScVal.scvSymbol("Exit"),
            xdr.ScVal.scvU64(new xdr.Uint64(BigInt(id))),
          ]),
          durability: xdr.ContractDataDurability.persistent(),
        }),
      );
    const balance = (holder: string): xdr.LedgerKey =>
      StrKey.isValidContract(holder)
        ? xdr.LedgerKey.contractData(
            new xdr.LedgerKeyContractData({
              contract: new Address(v.token).toScAddress(),
              key: xdr.ScVal.scvVec([
                xdr.ScVal.scvSymbol("Balance"),
                new Address(holder).toScVal(),
              ]),
              durability: xdr.ContractDataDurability.persistent(),
            }),
          )
        : xdr.LedgerKey.account(
            new xdr.LedgerKeyAccount({ accountId: Keypair.fromPublicKey(holder).xdrAccountId() }),
          );
    if (fn === "claim") return [exit(v.exitTail)];
    if (fn !== "transact") return [];
    const ext = decodeExtData(args[1] as xdr.ScVal);
    const payout = -ext.extAmount;
    if (v.queues(payout, ext.fee)) return [exit(v.exitTail)];
    if (payout + ext.fee <= 0n) return [];
    return [
      balance(v.address),
      ...(payout > 0n ? [balance(ext.recipient)] : []),
      ...(ext.fee > 0n ? [balance(ext.relayer)] : []),
    ];
  }

  // Whether a transaction's read-write footprint holds what the call writes that depends on the
  // vault's state when it is applied.
  #covers(tx: Transaction, fn: string, args: xdr.ScVal[]): boolean {
    const data = tx.toEnvelope().v1().tx().ext().sorobanData();
    const writes = new Set(
      data
        .resources()
        .footprint()
        .readWrite()
        .map((k) => k.toXDR("base64")),
    );
    return this.#written(fn, args).every((k) => writes.has(k.toXDR("base64")));
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
        diagnosticEvents: this.diagnosticsInMeta
          ? (record.diagnostics ?? []).map((d) => xdr.DiagnosticEvent.fromXDR(d, "base64"))
          : [],
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
        // The footprint holds what the call writes that depends on the vault's state now.
        const written = this.#written(fn, args);
        this.vault.dryRun = true;
        try {
          const result = this.#execute(fn, args, source);
          const data = new SorobanDataBuilder().setResourceFee(this.simulated?.fee ?? 1000);
          if (this.simulated !== undefined) {
            const { readOnly, readWrite, instructions, readBytes, writeBytes } = this.simulated;
            data
              .setFootprint(readOnly, readWrite)
              .setResources(instructions, readBytes, writeBytes);
          } else {
            data.setFootprint([], written);
          }
          return {
            transactionData: data.build().toXDR("base64"),
            minResourceFee: String(this.simulated?.fee ?? 1000),
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
        this.sent.push(tx);
        const { fn, args, source } = this.#invoke(tx);
        const others = this.beforeApply;
        this.beforeApply = undefined;
        others?.();
        const failed = this.failNext > 0;
        const conflict =
          !failed &&
          (this.conflictNext > 0 || (this.enforceFootprint && !this.#covers(tx, fn, args)));
        if (failed) this.failNext--;
        else if (this.conflictNext > 0) this.conflictNext--;
        if (failed || conflict) {
          const error = conflict
            ? xdr.ScError.sceStorage(xdr.ScErrorCode.scecExceededLimit())
            : xdr.ScError.sceContract(121);
          this.records.set(hash, {
            status: "FAILED",
            ledger: this.vault.ledger,
            returnValue: xdr.ScVal.scvVoid(),
            events: [],
            diagnostics: [diagnostic(error)],
          });
          return { status: "PENDING", hash, latestLedger: this.vault.ledger };
        }
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
          ...(record.diagnostics === undefined || this.diagnosticsInMeta
            ? {}
            : { diagnosticEventsXdr: record.diagnostics }),
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
    const counts = new Map<number, number>();
    const all = this.vault.events.map((e) => {
      const n = (counts.get(e.ledger) ?? 0) + 1;
      counts.set(e.ledger, n);
      return { e, id: eventId(e.ledger, n) };
    });
    const after = pagination.cursor;
    const from = after === undefined ? (start ?? 0) : ledgerOf(after);
    const last = Math.min(this.vault.ledger, from + this.scanLedgers - 1);
    const selected = all
      .filter(({ e, id }) => (after === undefined ? e.ledger >= from : id > after))
      .filter(({ e }) => e.ledger <= last)
      .slice(0, limit);
    const full = selected.length === limit;
    return {
      events: selected.map(({ e, id }) => ({
        type: "contract",
        ledger: e.ledger,
        ledgerClosedAt: new Date(this.closeTime(e.ledger) * 1000).toISOString(),
        contractId: this.vault.address,
        id,
        pagingToken: id,
        txHash: e.txHash,
        inSuccessfulContractCall: true,
        topic: [xdr.ScVal.scvSymbol(e.topic).toXDR("base64")],
        value: map(e.fields).toXDR("base64"),
      })),
      cursor: full ? (selected[selected.length - 1] as { id: string }).id : ledgerEnd(last),
      latestLedger: this.vault.ledger,
      oldestLedger: this.oldestLedger,
      latestLedgerCloseTime: String(this.closeTime(this.vault.ledger)),
      oldestLedgerCloseTime: String(this.closeTime(this.oldestLedger)),
    };
  }
}

export const keypairFor = (label: string): Keypair =>
  Keypair.fromRawEd25519Seed(
    Buffer.from(
      hexToBytes(bytesToHex(new TextEncoder().encode(label.padEnd(32, "-").slice(0, 32)))),
    ),
  );
