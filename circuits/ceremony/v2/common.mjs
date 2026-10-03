import { bn254 } from "@noble/curves/bn254.js";
import { createHash } from "node:crypto";

// Contributors run the kit on its own, so it repeats the pins of scripts/circom.mjs and
// scripts/ptau.mjs instead of importing them. The key is only valid for this exact r1cs: the
// circuit at the git tag circuit-v2-freeze, compiled by circom 2.2.3 with --O2.
export const R1CS_SHA256 = "b838223d6261f12c35caf3c87d9f80a69ecaeed115251702fe8fefce07bb3fb5";

// Hermez phase 1, power 15. The blake2b is the value the snarkjs README publishes for this file,
// so any mirror will do.
export const PTAU_NAME = "powersOfTau28_hez_final_15.ptau";
export const PTAU_BLAKE2B =
  "982372c867d229c236091f767e703253249a9b432c1710b4f326306bfa2428a1" +
  "7b06240359606cfe4d580b10a5a1f63fbed499527069c18ae17060472969ae6e";

export const PUBLIC_INPUTS = 8;
export const BEACON_ITERATIONS_EXP = 10;
export const MIN_CONTRIBUTIONS = 3;

// BN254 base field and group order.
const Q = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// snarkjs reports progress through info and failures through error; info would also print the
// free-text contributor names unescaped.
export const quiet = {
  info: () => {},
  debug: () => {},
  warn: (m) => console.warn(m),
  error: (m) => console.error(m),
};

export function run(usage, main) {
  const argv = process.argv.slice(2);
  if (argv.includes("--help") || argv.includes("-h")) {
    console.log(usage);
    return;
  }
  main(argv).then(
    () => finish(0),
    (e) => {
      console.error(`\nERROR: ${e.message}\n`);
      return finish(1);
    },
  );
}

// snarkjs keeps curve worker threads alive. Stopping them lets the process end by itself, which
// unlike process.exit() never cuts off output still buffered for a pipe.
async function finish(code) {
  process.exitCode = code;
  await globalThis.curve_bn128?.terminate();
}

export async function step(label, work) {
  console.log(`${label}...`);
  const started = Date.now();
  const out = await work();
  console.log(`  done in ${((Date.now() - started) / 1000).toFixed(1)} s`);
  return out;
}

export const digest = (data, algorithm = "sha256") =>
  createHash(algorithm).update(data).digest("hex");

export function expectHash(data, algorithm, expected, mismatch) {
  const actual = digest(data, algorithm);
  if (actual !== expected) {
    throw new Error(`${mismatch}: its ${algorithm} is ${actual}, not ${expected}`);
  }
  return actual;
}

// Every file is read once and snarkjs gets the same bytes in memory, so what is hashed and
// parsed is exactly what is verified, contributed to or written out.
export const mem = (data) => ({ type: "mem", data });

export function parseHex(value, bytes, what) {
  const hex = String(value ?? "")
    .trim()
    .toLowerCase();
  if (!new RegExp(`^[0-9a-f]{${bytes * 2}}$`).test(hex)) {
    throw new Error(`${what} must be ${bytes * 2} hex characters, got "${value ?? ""}"`);
  }
  return hex;
}

// The name is stored in the zkey and published with it forever. snarkjs silently cuts it at 64
// characters, and printable ASCII keeps it from hiding anything when it is displayed.
export function checkName(name) {
  if (!/^[\x20-\x7e]{1,64}$/.test(name) || name.trim() !== name) {
    throw new Error(
      "the name must be 1 to 64 printable ASCII characters without leading or trailing spaces",
    );
  }
  if (/\S@\S+\.\S/.test(name)) {
    throw new Error('the name looks like an email address; use a handle: "Name (github: handle)"');
  }
}

export const show = (name) => (name === undefined ? "(no name)" : JSON.stringify(name));

function cursor(buf, what) {
  let at = 0;
  const take = (n) => {
    if (at + n > buf.length) throw new Error(`${what} is truncated`);
    at += n;
    return buf.subarray(at - n, at);
  };
  return {
    take,
    u8: () => take(1)[0],
    u32: () => take(4).readUInt32LE(0),
    since: (start) => Buffer.from(buf.subarray(start, at)),
    get at() {
      return at;
    },
    get left() {
      return buf.length - at;
    },
  };
}

const littleEndian = (bytes) => BigInt(`0x${Buffer.from(bytes).reverse().toString("hex")}`);

function modPow(base, exp, mod) {
  let out = 1n;
  for (base %= mod; exp > 0n; exp >>= 1n, base = (base * base) % mod) {
    if (exp & 1n) out = (out * base) % mod;
  }
  return out;
}

// zkey points hold each coordinate x as x * 2^256 mod q, little-endian.
const MONTGOMERY_INV = modPow(2n ** 256n % Q, Q - 2n, Q);

function coordinate(bytes) {
  const v = littleEndian(bytes);
  if (v >= Q) throw new Error("a zkey point has a coordinate outside the field");
  return (v * MONTGOMERY_INV) % Q;
}

const bigEndian = (v) => Buffer.from(v.toString(16).padStart(64, "0"), "hex");

// noble reads (0, 0) as the point at infinity and lets it pass assertValidity, but no key or
// zkey point may be the identity.
export function validPoint(point, error) {
  try {
    point.assertValidity();
  } catch {
    throw new Error(error);
  }
  if (point.is0()) throw new Error(error);
  return point;
}

// snarkjs checks the chain with pairings, which hold only for points in the prime-order groups,
// yet it reads zkey points without checking them, so each one is checked here. The bytes
// returned are the uncompressed encoding snarkjs hashes: big-endian coordinates, and for G2 each
// Fq2 element as its c1 half before its c0 half.
function g1(bytes) {
  const [x, y] = [0, 32].map((at) => coordinate(bytes.subarray(at, at + 32)));
  validPoint(bn254.G1.Point.fromAffine({ x, y }), "a zkey G1 point is not in G1");
  return Buffer.concat([x, y].map(bigEndian));
}

function g2(bytes) {
  const [x0, x1, y0, y1] = [0, 32, 64, 96].map((at) => coordinate(bytes.subarray(at, at + 32)));
  const { Fp2 } = bn254.fields;
  const point = bn254.G2.Point.fromAffine({
    x: Fp2.fromBigTuple([x0, x1]),
    y: Fp2.fromBigTuple([y0, y1]),
  });
  validPoint(point, "a zkey G2 point is not in G2");
  return Buffer.concat([x1, x0, y1, y0].map(bigEndian));
}

function readContribution(c) {
  const start = c.at;
  const deltaAfter = c.take(64);
  const g1S = c.take(64);
  const g1Sx = c.take(64);
  const g2Spx = c.take(128);
  const transcript = c.take(64);
  const type = c.u32();
  const params = cursor(c.take(c.u32()), "contribution parameters");
  const out = { type };
  let last = 0;
  while (params.left > 0) {
    const id = params.u8();
    if (id <= last) throw new Error("contribution parameters are out of order");
    last = id;
    if (id === 1) {
      out.name = new TextDecoder("utf-8", { fatal: true }).decode(params.take(params.u8()));
    } else if (id === 2) {
      out.iterationsExp = params.u8();
    } else if (id === 3) {
      out.beaconHash = Buffer.from(params.take(params.u8())).toString("hex");
    } else {
      throw new Error(`unknown contribution parameter ${id}`);
    }
  }
  const beacon = out.iterationsExp !== undefined && out.beaconHash !== undefined;
  if (type === 0 ? last > 1 : type !== 1 || !beacon) {
    throw new Error(`a contribution of type ${type} has the wrong parameters`);
  }
  // The contribution hash snarkjs prints: the BLAKE2b-512 of the contribution's public key.
  out.hash = createHash("blake2b512")
    .update(g1(deltaAfter))
    .update(g1(g1S))
    .update(g1(g1Sx))
    .update(g2(g2Spx))
    .update(transcript)
    .digest("hex");
  out.raw = c.since(start);
  return out;
}

// Reads what the ceremony tracks in a zkey: the circuit hash and every contribution in the order
// they were made, with each point checked on its own. How the points relate to each other is what
// snarkjs zkey verify checks.
export function readZkey(data, label) {
  const file = cursor(data, label);
  if (file.take(4).toString("latin1") !== "zkey" || file.u32() !== 1) {
    throw new Error(`${label} is not a version 1 zkey file`);
  }
  const sections = new Map();
  for (let i = file.u32(); i > 0; i--) {
    const id = file.u32();
    const length = Number(file.take(8).readBigUInt64LE(0));
    if (sections.has(id)) throw new Error(`${label} repeats section ${id}`);
    sections.set(id, file.take(length));
  }
  const section = (id) => {
    if (!sections.has(id)) throw new Error(`${label} has no section ${id}`);
    return sections.get(id);
  };

  if (section(1).readUInt32LE(0) !== 1) throw new Error(`${label} is not a Groth16 zkey`);
  const header = cursor(section(2), `${label} header`);
  const prime = () => (header.u32() === 32 ? littleEndian(header.take(32)) : 0n);
  if (prime() !== Q || prime() !== R) throw new Error(`${label} is not over BN254`);
  header.take(12); // nVars, nPublic and domainSize, which snarkjs zkey verify checks
  // alpha1, beta1, beta2, gamma2, delta1 and delta2
  for (const point of [g1, g1, g2, g2, g1, g2]) point(header.take(point === g1 ? 64 : 128));
  if (header.left !== 0) throw new Error(`${label} header has trailing bytes`);

  const mpc = cursor(section(10), `${label} contributions`);
  const csHash = Buffer.from(mpc.take(64));
  const contributions = [];
  for (let i = mpc.u32(); i > 0; i--) contributions.push(readContribution(mpc));
  if (mpc.left !== 0) throw new Error(`${label} has trailing bytes after its contributions`);
  return { csHash, contributions };
}

// A valid chain can also grow from an older zkey, which drops every contribution made after it.
// Comparing each earlier record byte for byte also covers the names, which the contribution
// hashes leave out.
export function newContribution(prev, next) {
  if (!prev.csHash.equals(next.csHash)) throw new Error("the zkey is for a different circuit");
  const expected = prev.contributions.length + 1;
  if (next.contributions.length !== expected) {
    throw new Error(
      `the zkey must hold the ${expected - 1} earlier contributions plus one, but holds ` +
        `${next.contributions.length}`,
    );
  }
  prev.contributions.forEach((c, i) => {
    if (!c.raw.equals(next.contributions[i].raw)) {
      throw new Error(`contribution #${i + 1} differs from the one in the previous zkey`);
    }
  });
  return next.contributions[expected - 1];
}
