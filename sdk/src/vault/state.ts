import { Address, Asset, MuxedAccount, StrKey, scValToBigInt, xdr } from "@stellar/stellar-base";
import { bytesToHex } from "../bytes.ts";
import { fail } from "../errors.ts";
import { isMuxedAccountId } from "../extdata.ts";
import { type SorobanRpc, keyId } from "../net/rpc.ts";
import { Struct } from "./scval.ts";

// The vault's storage keys are a #[contracttype] enum: a vector of the variant's symbol and its
// fields. Clients read them with getLedgerEntries, which takes no source account.
const dataKey = (variant: string, ...fields: xdr.ScVal[]): xdr.ScVal =>
  xdr.ScVal.scvVec([xdr.ScVal.scvSymbol(variant), ...fields]);

function contractDataKey(
  contract: string,
  key: xdr.ScVal,
  durability: "persistent" | "temporary" = "persistent",
): xdr.LedgerKey {
  return xdr.LedgerKey.contractData(
    new xdr.LedgerKeyContractData({
      contract: new Address(contract).toScAddress(),
      key,
      durability:
        durability === "persistent"
          ? xdr.ContractDataDurability.persistent()
          : xdr.ContractDataDurability.temporary(),
    }),
  );
}

const instanceKey = (contract: string): xdr.LedgerKey =>
  contractDataKey(contract, xdr.ScVal.scvLedgerKeyContractInstance());

function baseAccount(address: string): string {
  return isMuxedAccountId(address)
    ? MuxedAccount.fromAddress(address, "0").baseAccount().accountId()
    : address;
}

export const accountKey = (account: string): xdr.LedgerKey =>
  xdr.LedgerKey.account(
    new xdr.LedgerKeyAccount({
      accountId: xdr.PublicKey.publicKeyTypeEd25519(
        StrKey.decodeEd25519PublicKey(baseAccount(account)),
      ),
    }),
  );

function trustlineKey(account: string, assetName: string): xdr.LedgerKey {
  const [code, issuer] = assetName.split(":") as [string, string];
  return xdr.LedgerKey.trustline(
    new xdr.LedgerKeyTrustLine({
      accountId: xdr.PublicKey.publicKeyTypeEd25519(
        StrKey.decodeEd25519PublicKey(baseAccount(account)),
      ),
      asset: new Asset(code, issuer).toTrustLineXDRObject(),
    }),
  );
}

export interface VaultConfig {
  readonly token: string;
  readonly domain: bigint;
  readonly delaySmall: bigint;
  readonly delayLarge: bigint;
}

export interface VaultLimits {
  readonly minDeposit: bigint;
  readonly maxDeposit: bigint;
  readonly maxDailyPerDepositor: bigint;
  readonly tvlCap: bigint;
  readonly maxDailyOutflow: bigint;
  readonly maxFee: bigint;
  readonly largeDepositThreshold: bigint;
}

export interface VaultStatus {
  readonly depositsPaused: boolean;
  readonly transfersPaused: boolean;
  readonly haltedUntil: bigint;
  readonly nextDepositId: bigint;
  readonly tvl: bigint;
  readonly pendingTotal: bigint;
  readonly outflowDay: bigint;
  readonly outflow: bigint;
  // Queued exits hold the IDs from exitHead up to, not including, exitTail.
  readonly exitHead: bigint;
  readonly exitTail: bigint;
  readonly queuedTotal: bigint;
}

export interface VaultInstance {
  readonly wasmHash: string;
  readonly config: VaultConfig;
  readonly limits: VaultLimits;
  readonly status: VaultStatus;
  readonly latestLedger: number;
}

export interface RootHistory {
  readonly roots: readonly bigint[];
  readonly newest: number;
  readonly nextLeaf: number;
  // The ledger the RPC answered at.
  readonly ledger: number;
}

export interface PendingDepositEntry {
  readonly depositor: string;
  readonly flag: number | undefined;
  // Zero while the deposit is not flagged.
  readonly flaggedAt: bigint;
}

function parseInstance(data: xdr.LedgerEntryData): Omit<VaultInstance, "latestLedger"> {
  const val = data.contractData().val();
  if (val.switch().name !== "scvContractInstance") fail("rpc_error", "not a contract instance");
  const instance = val.instance();
  if (instance.executable().switch().name !== "contractExecutableWasm") {
    fail("deployment_mismatch", "the vault is not a wasm contract");
  }
  const storage = new Map<string, xdr.ScVal>();
  for (const entry of instance.storage() ?? [])
    storage.set(entry.key().toXDR("base64"), entry.val());
  const field = (variant: string): Struct =>
    new Struct(storage.get(dataKey(variant).toXDR("base64")), variant);
  const config = field("Config");
  const limits = field("Limits");
  const status = field("Status");
  return {
    wasmHash: bytesToHex(Uint8Array.from(instance.executable().wasmHash())),
    config: {
      token: config.address("token"),
      domain: config.u256("domain"),
      delaySmall: config.u64("delay_small"),
      delayLarge: config.u64("delay_large"),
    },
    limits: {
      minDeposit: limits.i128("min_deposit"),
      maxDeposit: limits.i128("max_deposit"),
      maxDailyPerDepositor: limits.i128("max_daily_per_depositor"),
      tvlCap: limits.i128("tvl_cap"),
      maxDailyOutflow: limits.i128("max_daily_outflow"),
      maxFee: limits.i128("max_fee"),
      largeDepositThreshold: limits.i128("large_deposit_threshold"),
    },
    status: {
      depositsPaused: status.bool("deposits_paused"),
      transfersPaused: status.bool("transfers_paused"),
      haltedUntil: status.u64("halted_until"),
      nextDepositId: status.u64("next_deposit_id"),
      tvl: status.i128("tvl"),
      pendingTotal: status.i128("pending_total"),
      outflowDay: status.u64("outflow_day"),
      outflow: status.i128("outflow"),
      exitHead: status.u64("exit_head"),
      exitTail: status.u64("exit_tail"),
      queuedTotal: status.i128("queued_total"),
    },
  };
}

// Reads the vault's state straight from the ledger. None of these reads names a user account,
// so none of them hints at an upcoming spend.
export class VaultReader {
  readonly #rpc: SorobanRpc;
  readonly vault: string;

  constructor(rpc: SorobanRpc, vault: string) {
    this.#rpc = rpc;
    this.vault = vault;
  }

  async instance(): Promise<VaultInstance> {
    const key = instanceKey(this.vault);
    const { entries, latestLedger } = await this.#rpc.getLedgerEntries([key]);
    const entry = entries.get(keyId(key));
    if (entry === undefined) fail("deployment_mismatch", "the pinned vault does not exist");
    return { ...parseInstance(entry.data), latestLedger };
  }

  async rootHistory(): Promise<RootHistory> {
    const rootsKey = contractDataKey(this.vault, dataKey("Roots"));
    const nextKey = contractDataKey(this.vault, dataKey("NextLeaf"));
    const { entries, latestLedger } = await this.#rpc.getLedgerEntries([rootsKey, nextKey]);
    const roots = entries.get(keyId(rootsKey));
    const next = entries.get(keyId(nextKey));
    if (roots === undefined || next === undefined) fail("rpc_error", "the vault's tree is missing");
    const ring = new Struct(roots.data.contractData().val(), "root history");
    const nextLeaf = next.data.contractData().val();
    if (nextLeaf.switch().name !== "scvU64") fail("rpc_error", "the next leaf index is not a u64");
    return {
      roots: ring.vecU256("roots"),
      newest: ring.u32("newest"),
      nextLeaf: Number(nextLeaf.u64().toString()),
      ledger: latestLedger,
    };
  }

  async pending(id: bigint): Promise<PendingDepositEntry | undefined> {
    const key = contractDataKey(
      this.vault,
      dataKey("Pending", xdr.ScVal.scvU64(new xdr.Uint64(id))),
    );
    const { entries } = await this.#rpc.getLedgerEntries([key]);
    const entry = entries.get(keyId(key));
    if (entry === undefined) return undefined;
    const d = new Struct(entry.data.contractData().val(), "pending deposit");
    return {
      depositor: d.address("depositor"),
      flag: d.optionU32("flag"),
      flaggedAt: d.u64("flagged_at"),
    };
  }

  async depositorDayTotal(depositor: string, day: bigint): Promise<bigint> {
    const key = contractDataKey(
      this.vault,
      dataKey(
        "DepositorDay",
        new Address(depositor).toScVal(),
        xdr.ScVal.scvU64(new xdr.Uint64(day)),
      ),
      "temporary",
    );
    const { entries } = await this.#rpc.getLedgerEntries([key]);
    const entry = entries.get(keyId(key));
    if (entry === undefined) return 0n;
    const val = entry.data.contractData().val();
    if (val.switch().name !== "scvI128") fail("rpc_error", "a day total is not an i128");
    return scValToBigInt(val);
  }

  // The ledger entries an unshield destination needs: the account and, for an issued asset, its
  // trustline; or the contract's instance.
  async destination(
    address: string,
    assetName: string,
  ): Promise<{
    readonly exists: boolean;
    readonly createdLedger: number | undefined;
    readonly trustline: { readonly authorized: boolean; readonly room: bigint } | undefined;
    readonly latestLedger: number;
  }> {
    if (StrKey.isValidContract(address)) {
      const key = instanceKey(address);
      const { entries, latestLedger } = await this.#rpc.getLedgerEntries([key]);
      return {
        exists: entries.has(keyId(key)),
        createdLedger: undefined,
        trustline: undefined,
        latestLedger,
      };
    }
    const keys = [accountKey(address)];
    if (assetName !== "native") keys.push(trustlineKey(address, assetName));
    const { entries, latestLedger } = await this.#rpc.getLedgerEntries(keys);
    const account = entries.get(keyId(keys[0] as xdr.LedgerKey));
    if (account === undefined)
      return { exists: false, createdLedger: undefined, trustline: undefined, latestLedger };
    // A new account's sequence number starts at its creation ledger shifted left by 32 bits.
    const seq = BigInt(account.data.account().seqNum().toString());
    let trustline: { authorized: boolean; room: bigint } | undefined;
    const line = keys[1] === undefined ? undefined : entries.get(keyId(keys[1]));
    if (line !== undefined) {
      const t = line.data.trustLine();
      trustline = {
        authorized: (t.flags() & 1) === 1,
        room: BigInt(t.limit().toString()) - BigInt(t.balance().toString()),
      };
    }
    return { exists: true, createdLedger: Number(seq >> 32n), trustline, latestLedger };
  }
}
