import { CyphrasError } from "../errors.ts";
import type { ContractEvent } from "../net/rpc.ts";
import { Struct } from "./scval.ts";

// The vault events the SDK reads from RPC: each has a single snake_case topic and map-shaped data.
// Amounts of an exit are its payout to the recipient and its fee to the relayer.
export type VaultEvent =
  | {
      readonly kind: "new_commitment";
      readonly index: number;
      readonly commitment: bigint;
      readonly ciphertext: Uint8Array;
    }
  | { readonly kind: "new_nullifier"; readonly nullifier: bigint }
  | {
      readonly kind: "exit_queued";
      readonly id: number;
      readonly payout: bigint;
      readonly fee: bigint;
    }
  // A part payment of a queued or stranded exit, and what it still owes.
  | {
      readonly kind: "exit_paid";
      readonly id: number;
      readonly payoutLeft: bigint;
      readonly feeLeft: bigint;
    }
  // What a released exit still owes after a part the asset contract refused.
  | {
      readonly kind: "exit_stranded";
      readonly id: number;
      readonly payoutLeft: bigint;
      readonly feeLeft: bigint;
    }
  // exitId is set when release or claim completes an exit, and absent when transact paid at once.
  | { readonly kind: "settled"; readonly exitId: number | undefined }
  | { readonly kind: "other"; readonly topic: string };

export function decodeVaultEvent(event: Pick<ContractEvent, "topic" | "value">): VaultEvent {
  const [first] = event.topic;
  if (event.topic.length !== 1 || first?.switch().name !== "scvSymbol") {
    throw new CyphrasError("rpc_error", "a vault event without a single symbol topic");
  }
  const topic = first.sym().toString();
  switch (topic) {
    case "new_commitment": {
      const data = new Struct(event.value, topic);
      return {
        kind: topic,
        index: Number(data.u64("index")),
        commitment: data.u256("commitment"),
        ciphertext: data.bytes("encrypted_output"),
      };
    }
    case "new_nullifier":
      return { kind: topic, nullifier: new Struct(event.value, topic).u256("nullifier") };
    case "exit_queued": {
      const data = new Struct(event.value, topic);
      return {
        kind: topic,
        id: Number(data.u64("id")),
        payout: -data.i128("ext_amount"),
        fee: data.i128("fee"),
      };
    }
    case "exit_paid": {
      const data = new Struct(event.value, topic);
      return {
        kind: topic,
        id: Number(data.u64("id")),
        payoutLeft: data.i128("payout_left"),
        feeLeft: data.i128("fee_left"),
      };
    }
    case "exit_stranded": {
      const data = new Struct(event.value, topic);
      return {
        kind: topic,
        id: Number(data.u64("id")),
        payoutLeft: data.i128("payout"),
        feeLeft: data.i128("fee"),
      };
    }
    case "settled": {
      const exitId = new Struct(event.value, topic).optionU64("exit_id");
      return { kind: topic, exitId: exitId === undefined ? undefined : Number(exitId) };
    }
    default:
      return { kind: "other", topic };
  }
}
