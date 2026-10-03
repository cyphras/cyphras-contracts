import { createHash } from "node:crypto";
import { P } from "./babyjub.mjs";

const hex32 = (x) => "0x" + x.toString(16).padStart(64, "0");

// A vault's domain: OS2IP(SHA-256("cyphras/v2/domain/" || network || "/" || asset)) mod p, where
// asset is "native" or "CODE:ISSUER".
export function domain(network, asset) {
  const preimage = `cyphras/v2/domain/${network}/${asset}`;
  return BigInt("0x" + createHash("sha256").update(preimage).digest("hex")) % P;
}

const DOMAIN_CASES = [
  ["mainnet", "native"],
  ["testnet", "native"],
  ["mainnet", "USDC:GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN"],
  ["testnet", "USDC:GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5"],
];

export function domainVectors() {
  return {
    description: "Vault domain vectors.",
    format: "Field elements are 0x-prefixed 32-byte big-endian hex.",
    derivation: 'domain = OS2IP(SHA-256("cyphras/v2/domain/" || network || "/" || asset)) mod p',
    domains: DOMAIN_CASES.map(([network, asset]) => ({
      network,
      asset,
      preimage: `cyphras/v2/domain/${network}/${asset}`,
      domain: hex32(domain(network, asset)),
    })),
  };
}
