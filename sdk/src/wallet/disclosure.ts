import { decodeAddress, encodeAddress } from "../address.ts";
import { L, equalPoints, scalarMul } from "../babyjub.ts";
import { toHex32 } from "../bytes.ts";
import { ephemeralKey } from "../encryption.ts";
import { CyphrasError, fail } from "../errors.ts";
import { P } from "../field.ts";
import { type Network, isNetwork } from "../keys.ts";
import { PAGE_SIZE } from "../merkle.ts";
import type { IndexerClient } from "../net/indexer.ts";
import type { SorobanRpc } from "../net/rpc.ts";
import { MAX_VALUE, noteCommitment } from "../notes.ts";
import { decodeVaultEvent } from "../vault/events.ts";
import type { WalletState } from "./state.ts";

/**
 * A payment disclosure (encryption.md): it proves one note to a third party without a viewing
 * key. `esk` is present when the discloser built the output, which only its sender could have.
 */
export interface PaymentDisclosure {
  readonly version: 2;
  readonly network: Network;
  readonly vault: string;
  readonly tx_hash: string;
  readonly leaf_index: number;
  readonly address: string;
  readonly note: { readonly value: string; readonly rcm: string };
  readonly esk?: string;
}

export function disclose(
  state: WalletState,
  network: Network,
  vault: string,
  txHash: string,
  leafIndex: number,
  ownAddress: (d: Uint8Array) => string,
): PaymentDisclosure {
  const base = { version: 2 as const, network, vault, tx_hash: txHash, leaf_index: leafIndex };
  // An output this wallet built for someone else; the outgoing key recovered its esk.
  const sent = state.sent.find((s) => s.pos === leafIndex && s.txHash === txHash);
  if (sent !== undefined) {
    return {
      ...base,
      address: sent.address,
      note: { value: sent.value.toString(), rcm: toHex32(sent.rcm) },
      esk: toHex32(sent.esk),
    };
  }
  const own = state.notes.find((n) => n.pos === leafIndex && n.txHash === txHash);
  if (own === undefined) {
    return fail("not_found", "no note of this wallet is at that leaf of that transaction");
  }
  // A note this wallet received; if it built the note itself, its plan kept the esk.
  const esk = state.plans.flatMap((p) => p.outputs).find((o) => o.cm === own.cm)?.esk;
  return {
    ...base,
    address: ownAddress(own.d),
    note: { value: own.value.toString(), rcm: toHex32(own.rcm) },
    ...(esk === undefined ? {} : { esk: toHex32(esk) }),
  };
}

/** What a disclosure check established. */
export interface DisclosureCheck {
  readonly value: bigint;
  readonly address: string;
  readonly txHash: string;
  readonly leafIndex: number;
  // esk * g_d equals the output's ephemeral key: the discloser built the output.
  readonly senderProven: boolean;
  // RPC still holds the transaction and its events show the commitment at that leaf.
  readonly confirmedByRpc: boolean;
}

const HEX64 = /^0x[0-9a-f]{64}$/;

function parse(doc: unknown, network: Network, vault: string) {
  const bad = (what: string): never =>
    fail("invalid_argument", `the disclosure's ${what} is invalid`);
  if (typeof doc !== "object" || doc === null) bad("format");
  const d = doc as Record<string, unknown>;
  if (d["version"] !== 2) bad("version");
  if (!isNetwork(d["network"]) || d["network"] !== network) bad("network");
  if (d["vault"] !== vault) bad("vault");
  const txHash = d["tx_hash"];
  if (typeof txHash !== "string" || !/^[0-9a-f]{64}$/.test(txHash)) bad("tx_hash");
  const leafIndex = d["leaf_index"];
  if (typeof leafIndex !== "number" || !Number.isSafeInteger(leafIndex) || leafIndex < 0)
    bad("leaf_index");
  const note = d["note"] as Record<string, unknown> | undefined;
  const value = note?.["value"];
  const rcm = note?.["rcm"];
  if (typeof value !== "string" || !/^(0|[1-9][0-9]*)$/.test(value) || BigInt(value) > MAX_VALUE)
    bad("value");
  if (typeof rcm !== "string" || !HEX64.test(rcm) || BigInt(rcm) >= P) bad("rcm");
  const esk = d["esk"];
  if (
    esk !== undefined &&
    (typeof esk !== "string" || !HEX64.test(esk) || BigInt(esk) === 0n || BigInt(esk) >= L)
  ) {
    bad("esk");
  }
  return {
    txHash: txHash as string,
    leafIndex: leafIndex as number,
    address: decodeAddress(network, d["address"]),
    value: BigInt(value as string),
    rcm: BigInt(rcm as string),
    esk: esk === undefined ? undefined : BigInt(esk as string),
  };
}

// Checks a disclosure without keys: the note's commitment must be the leaf at that index, added
// by that transaction on that vault, and an esk must reproduce the output's ephemeral key.
export async function verifyDisclosure(
  doc: unknown,
  network: Network,
  vault: string,
  indexer: IndexerClient,
  rpc: SorobanRpc | undefined,
): Promise<DisclosureCheck> {
  const p = parse(doc, network, vault);
  const cm = noteCommitment({ value: p.value, gd: p.address.gd, pkd: p.address.pkd, rcm: p.rcm });
  const page = await indexer.leaves(Math.floor(p.leafIndex / PAGE_SIZE));
  const leaf = page[p.leafIndex % PAGE_SIZE];
  if (leaf === undefined || leaf.index !== p.leafIndex)
    fail("not_found", "the leaf is not in the tree");
  if (leaf.commitment !== cm) fail("invalid_argument", "the note is not the one at that leaf");
  if (leaf.txHash !== p.txHash) fail("invalid_argument", "another transaction added that leaf");
  let senderProven = false;
  if (p.esk !== undefined) {
    const epk = ephemeralKey(leaf.ciphertext);
    if (epk === undefined || !equalPoints(epk, scalarMul(p.address.gd, p.esk))) {
      fail("invalid_argument", "esk does not match the output's ephemeral key");
    }
    senderProven = true;
  }
  let confirmedByRpc = false;
  if (rpc !== undefined) {
    try {
      const tx = await rpc.getTransaction(p.txHash);
      confirmedByRpc = tx.events.some((e) => {
        if (e.contractId !== vault) return false;
        const decoded = decodeVaultEvent(e);
        return (
          decoded.kind === "new_commitment" &&
          decoded.index === p.leafIndex &&
          decoded.commitment === cm
        );
      });
    } catch (err) {
      if (!(err instanceof CyphrasError)) throw err;
    }
  }
  return {
    value: p.value,
    address: encodeAddress(network, p.address.d, p.address.pkd),
    txHash: p.txHash,
    leafIndex: p.leafIndex,
    senderProven,
    confirmedByRpc,
  };
}
