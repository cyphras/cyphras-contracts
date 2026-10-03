import { CyphrasError } from "../errors.ts";
import type { ContractEvent } from "../net/rpc.ts";
import { Struct } from "./scval.ts";

// The vault events the SDK reads from RPC: each has a single snake_case topic and map-shaped data.
export type VaultEvent =
  | {
      readonly kind: "new_commitment";
      readonly index: number;
      readonly commitment: bigint;
      readonly ciphertext: Uint8Array;
    }
  | { readonly kind: "new_nullifier"; readonly nullifier: bigint }
  | { readonly kind: "exit_queued"; readonly id: number }
  | { readonly kind: "other"; readonly topic: string };

export function decodeVaultEvent(event: ContractEvent): VaultEvent {
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
    case "exit_queued":
      return { kind: topic, id: Number(new Struct(event.value, topic).u64("id")) };
    default:
      return { kind: "other", topic };
  }
}
