import { Address, scValToBigInt, xdr } from "@stellar/stellar-base";
import { CyphrasError } from "../errors.ts";

// Readers for the ScVal shapes #[contracttype] produces. Structs are maps keyed by field name and
// read by name, so a field added to a vault type does not break them; a missing or mistyped field
// does.
export class Struct {
  readonly #fields: ReadonlyMap<string, xdr.ScVal>;
  readonly #what: string;

  constructor(value: xdr.ScVal | undefined, what: string) {
    this.#what = what;
    if (value === undefined || value.switch().name !== "scvMap") this.#fault("is not a struct");
    const fields = new Map<string, xdr.ScVal>();
    for (const entry of (value as xdr.ScVal).map() ?? []) {
      if (entry.key().switch().name !== "scvSymbol") this.#fault("has a key that is not a symbol");
      fields.set(entry.key().sym().toString(), entry.val());
    }
    this.#fields = fields;
  }

  #fault(detail: string): never {
    throw new CyphrasError("rpc_error", `the vault's ${this.#what} ${detail}`);
  }

  has(name: string): boolean {
    return this.#fields.has(name);
  }

  get(name: string): xdr.ScVal {
    const v = this.#fields.get(name);
    if (v === undefined) this.#fault(`lacks ${name}`);
    return v;
  }

  bool(name: string): boolean {
    const v = this.get(name);
    if (v.switch().name !== "scvBool") this.#fault(`${name} is not a bool`);
    return v.b();
  }

  u32(name: string): number {
    const v = this.get(name);
    if (v.switch().name !== "scvU32") this.#fault(`${name} is not a u32`);
    return v.u32();
  }

  u64(name: string): bigint {
    const v = this.get(name);
    if (v.switch().name !== "scvU64") this.#fault(`${name} is not a u64`);
    return scValToBigInt(v);
  }

  i128(name: string): bigint {
    const v = this.get(name);
    if (v.switch().name !== "scvI128") this.#fault(`${name} is not an i128`);
    return scValToBigInt(v);
  }

  u256(name: string): bigint {
    const v = this.get(name);
    if (v.switch().name !== "scvU256") this.#fault(`${name} is not a U256`);
    return scValToBigInt(v);
  }

  bytes(name: string): Uint8Array {
    const v = this.get(name);
    if (v.switch().name !== "scvBytes") this.#fault(`${name} is not bytes`);
    return Uint8Array.from(v.bytes());
  }

  address(name: string): string {
    return addressOf(this.get(name), `${this.#what}.${name}`);
  }

  optionU32(name: string): number | undefined {
    const v = this.get(name);
    if (v.switch().name === "scvVoid") return undefined;
    if (v.switch().name !== "scvU32") this.#fault(`${name} is not an Option<u32>`);
    return v.u32();
  }

  vecU256(name: string): bigint[] {
    const v = this.get(name);
    if (v.switch().name !== "scvVec") this.#fault(`${name} is not a vector`);
    return (v.vec() ?? []).map((item) => {
      if (item.switch().name !== "scvU256") this.#fault(`${name} holds a non-U256`);
      return scValToBigInt(item);
    });
  }
}

export function addressOf(value: xdr.ScVal, what: string): string {
  if (value.switch().name !== "scvAddress") {
    throw new CyphrasError("rpc_error", `${what} is not an address`);
  }
  return Address.fromScAddress(value.address()).toString();
}
