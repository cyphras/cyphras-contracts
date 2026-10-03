import { sha256 } from "@noble/hashes/sha2";
import { bytesToBigIntBE, utf8 } from "./bytes.ts";
import { P } from "./field.ts";
import type { Network } from "./keys.ts";

// The vault's per-deployment public input: OS2IP(SHA-256("cyphras/v2/domain/" || network || "/" ||
// asset)) mod p, where asset is the asset contract's name, "native" or "CODE:ISSUER".
export function computeDomain(network: Network, asset: string): bigint {
  return bytesToBigIntBE(sha256(utf8(`cyphras/v2/domain/${network}/${asset}`))) % P;
}
