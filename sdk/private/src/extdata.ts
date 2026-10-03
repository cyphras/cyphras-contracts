import { keccak_256 } from "@noble/hashes/sha3";
import { Address, StrKey, nativeToScVal, xdr } from "@stellar/stellar-base";
import { bigIntToBytesBE, bytesToBigIntBE, bytesToHex, hexToBytes } from "./bytes.ts";
import { CIPHERTEXT_LENGTH } from "./encryption.ts";
import { fail } from "./errors.ts";
import { P, isCanonical, mod } from "./field.ts";

const MAX_I128 = (1n << 127n) - 1n;
const MIN_I128 = -(1n << 127n);
const MAX_U32 = 0xffffffff;

// The external data a proof binds through extDataHash, field for field the vault's ExtData.
export interface ExtData {
  readonly vault: string;
  readonly networkId: Uint8Array;
  readonly deadline: number;
  readonly extAmount: bigint;
  readonly fee: bigint;
  readonly recipient: string;
  readonly relayer: string;
  readonly encryptedOutput0: Uint8Array;
  readonly encryptedOutput1: Uint8Array;
}

export function isAccountId(value: string): boolean {
  return StrKey.isValidEd25519PublicKey(value);
}

export function isContractId(value: string): boolean {
  return StrKey.isValidContract(value);
}

export function isMuxedAccountId(value: string): boolean {
  return StrKey.isValidMed25519PublicKey(value);
}

// The vault's ExtData.relayer is an Address: an account or a contract.
function isAddress(value: string): boolean {
  return isAccountId(value) || isContractId(value);
}

// The vault's ExtData.recipient is a MuxedAddress: an account, a muxed account or a contract.
function isMuxedAddress(value: string): boolean {
  return isAddress(value) || isMuxedAccountId(value);
}

export function checkExtData(ext: ExtData): void {
  if (!isContractId(ext.vault)) fail("invalid_argument", "ExtData.vault must be a contract");
  if (ext.networkId.length !== 32) fail("invalid_argument", "ExtData.network_id is 32 bytes");
  if (!Number.isInteger(ext.deadline) || ext.deadline < 0 || ext.deadline > MAX_U32) {
    fail("invalid_argument", "ExtData.deadline is a u32 ledger sequence");
  }
  for (const amount of [ext.extAmount, ext.fee]) {
    if (amount < MIN_I128 || amount > MAX_I128) fail("invalid_argument", "amount exceeds i128");
  }
  if (ext.fee < 0n) fail("invalid_argument", "ExtData.fee cannot be negative");
  if (!isMuxedAddress(ext.recipient)) fail("invalid_argument", "ExtData.recipient is invalid");
  if (!isAddress(ext.relayer)) fail("invalid_argument", "ExtData.relayer is invalid");
  if (
    ext.encryptedOutput0.length !== CIPHERTEXT_LENGTH ||
    ext.encryptedOutput1.length !== CIPHERTEXT_LENGTH
  ) {
    fail("invalid_argument", "both ciphertexts are 181 bytes");
  }
}

// js-xdr copies any Uint8Array it is given, so no Buffer is needed in browsers.
const opaque = (bytes: Uint8Array): xdr.ScVal =>
  xdr.ScVal.scvBytes(bytes as unknown as Parameters<typeof xdr.ScVal.scvBytes>[0]);

const symbolMap = (fields: [string, xdr.ScVal][]): xdr.ScVal =>
  xdr.ScVal.scvMap(
    // #[contracttype] structs encode as maps keyed by field name in sorted order
    [...fields]
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([key, val]) => new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol(key), val })),
  );

export function extDataToScVal(ext: ExtData): xdr.ScVal {
  checkExtData(ext);
  return symbolMap([
    ["vault", new Address(ext.vault).toScVal()],
    ["network_id", opaque(ext.networkId)],
    ["deadline", xdr.ScVal.scvU32(ext.deadline)],
    ["ext_amount", nativeToScVal(ext.extAmount, { type: "i128" })],
    ["fee", nativeToScVal(ext.fee, { type: "i128" })],
    ["recipient", new Address(ext.recipient).toScVal()],
    ["relayer", new Address(ext.relayer).toScVal()],
    ["encrypted_output0", opaque(ext.encryptedOutput0)],
    ["encrypted_output1", opaque(ext.encryptedOutput1)],
  ]);
}

export function extDataXdr(ext: ExtData): Uint8Array {
  return Uint8Array.from(extDataToScVal(ext).toXDR());
}

// keccak256(XDR(ScVal(ExtData))) mod p, as the vault recomputes it.
export function extDataHash(ext: ExtData): bigint {
  return bytesToBigIntBE(keccak_256(extDataXdr(ext))) % P;
}

export function publicAmount(extAmount: bigint, fee: bigint): bigint {
  return mod(extAmount - fee);
}

// A Groth16 proof in the host's uncompressed big-endian encoding: G1 as x || y and G2 as
// x.c1 || x.c0 || y.c1 || y.c0.
export interface HostProof {
  readonly a: Uint8Array;
  readonly b: Uint8Array;
  readonly c: Uint8Array;
}

// The vault's TxProof: the proof and every public input but domain, which the vault injects.
export interface TxProof {
  readonly proof: HostProof;
  readonly root: bigint;
  readonly publicAmount: bigint;
  readonly extDataHash: bigint;
  readonly inputNullifiers: readonly [bigint, bigint];
  readonly outputCommitments: readonly [bigint, bigint];
}

export interface AffineProof {
  readonly a: readonly [bigint, bigint];
  readonly b: readonly [readonly [bigint, bigint], readonly [bigint, bigint]];
  readonly c: readonly [bigint, bigint];
}

const be32 = (x: bigint): Uint8Array => bigIntToBytesBE(x, 32);

// snarkjs and the Prover interface write an Fq2 element as [c0, c1]; the host wants c1 first.
export function toHostProof(proof: AffineProof): HostProof {
  const [[x0, x1], [y0, y1]] = proof.b;
  return {
    a: Uint8Array.from([...be32(proof.a[0]), ...be32(proof.a[1])]),
    b: Uint8Array.from([...be32(x1), ...be32(x0), ...be32(y1), ...be32(y0)]),
    c: Uint8Array.from([...be32(proof.c[0]), ...be32(proof.c[1])]),
  };
}

export function fromHostProof(proof: HostProof): AffineProof {
  const word = (bytes: Uint8Array, i: number): bigint =>
    bytesToBigIntBE(bytes.subarray(32 * i, 32 * i + 32));
  return {
    a: [word(proof.a, 0), word(proof.a, 1)],
    b: [
      [word(proof.b, 1), word(proof.b, 0)],
      [word(proof.b, 3), word(proof.b, 2)],
    ],
    c: [word(proof.c, 0), word(proof.c, 1)],
  };
}

const u256 = (x: bigint): xdr.ScVal => {
  if (!isCanonical(x)) fail("invalid_argument", "public inputs are canonical field elements");
  return nativeToScVal(x, { type: "u256" });
};

export function txProofToScVal(p: TxProof): xdr.ScVal {
  return symbolMap([
    [
      "proof",
      symbolMap([
        ["a", opaque(p.proof.a)],
        ["b", opaque(p.proof.b)],
        ["c", opaque(p.proof.c)],
      ]),
    ],
    ["root", u256(p.root)],
    ["public_amount", u256(p.publicAmount)],
    ["ext_data_hash", u256(p.extDataHash)],
    ["input_nullifiers", xdr.ScVal.scvVec(p.inputNullifiers.map(u256))],
    ["output_commitments", xdr.ScVal.scvVec(p.outputCommitments.map(u256))],
  ]);
}

// The JSON forms the relayer's /v1/submit takes: binary values as lowercase hex of exact length,
// field elements as 32-byte big-endian hex, amounts as decimal strings.
export interface ExtDataJson {
  vault: string;
  network_id: string;
  deadline: number;
  ext_amount: string;
  fee: string;
  recipient: string;
  relayer: string;
  encrypted_output0: string;
  encrypted_output1: string;
}

export interface TxProofJson {
  a: string;
  b: string;
  c: string;
  root: string;
  public_amount: string;
  ext_data_hash: string;
  input_nullifiers: [string, string];
  output_commitments: [string, string];
}

export function extDataToJson(ext: ExtData): ExtDataJson {
  checkExtData(ext);
  return {
    vault: ext.vault,
    network_id: bytesToHex(ext.networkId),
    deadline: ext.deadline,
    ext_amount: ext.extAmount.toString(),
    fee: ext.fee.toString(),
    recipient: ext.recipient,
    relayer: ext.relayer,
    encrypted_output0: bytesToHex(ext.encryptedOutput0),
    encrypted_output1: bytesToHex(ext.encryptedOutput1),
  };
}

export function extDataFromJson(json: ExtDataJson): ExtData {
  const ext: ExtData = {
    vault: json.vault,
    networkId: hexToBytes(json.network_id),
    deadline: json.deadline,
    extAmount: BigInt(json.ext_amount),
    fee: BigInt(json.fee),
    recipient: json.recipient,
    relayer: json.relayer,
    encryptedOutput0: hexToBytes(json.encrypted_output0),
    encryptedOutput1: hexToBytes(json.encrypted_output1),
  };
  checkExtData(ext);
  return ext;
}

const fieldHex = (x: bigint): string => bytesToHex(be32(x));
const hexField = (hex: string): bigint => bytesToBigIntBE(hexToBytes(hex));

export function txProofToJson(p: TxProof): TxProofJson {
  return {
    a: bytesToHex(p.proof.a),
    b: bytesToHex(p.proof.b),
    c: bytesToHex(p.proof.c),
    root: fieldHex(p.root),
    public_amount: fieldHex(p.publicAmount),
    ext_data_hash: fieldHex(p.extDataHash),
    input_nullifiers: [fieldHex(p.inputNullifiers[0]), fieldHex(p.inputNullifiers[1])],
    output_commitments: [fieldHex(p.outputCommitments[0]), fieldHex(p.outputCommitments[1])],
  };
}

export function txProofFromJson(json: TxProofJson): TxProof {
  return {
    proof: { a: hexToBytes(json.a), b: hexToBytes(json.b), c: hexToBytes(json.c) },
    root: hexField(json.root),
    publicAmount: hexField(json.public_amount),
    extDataHash: hexField(json.ext_data_hash),
    inputNullifiers: [hexField(json.input_nullifiers[0]), hexField(json.input_nullifiers[1])],
    outputCommitments: [hexField(json.output_commitments[0]), hexField(json.output_commitments[1])],
  };
}
