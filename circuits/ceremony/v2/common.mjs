import { createHash } from "node:crypto";
import { closeSync, createReadStream, openSync, readSync } from "node:fs";

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
  // snarkjs zkey verify leaves the ptau file open, and Node warns when garbage collection closes
  // it; that warning is noise to a contributor, every other one is still printed.
  process.removeAllListeners("warning");
  process.on("warning", (w) => {
    if (!w.message.includes("on garbage collection")) console.warn(`${w.name}: ${w.message}`);
  });
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

export async function hashFile(path, algorithm = "sha256") {
  const hash = createHash(algorithm);
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return hash.digest("hex");
}

export async function expectHash(path, algorithm, expected, what) {
  const actual = await hashFile(path, algorithm);
  if (actual !== expected) {
    throw new Error(`${path} is not the ${what}: its ${algorithm} is ${actual}, not ${expected}`);
  }
  return actual;
}

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

function readAt(fd, position, length, path) {
  const buf = Buffer.alloc(length);
  if (readSync(fd, buf, 0, length, position) !== length) throw new Error(`${path} is truncated`);
  return buf;
}

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
  return Buffer.from(((v * MONTGOMERY_INV) % Q).toString(16).padStart(64, "0"), "hex");
}

// The uncompressed encodings snarkjs hashes: big-endian coordinates, and for G2 each Fq2 element
// as its c1 half before its c0 half.
const g1 = (p) => Buffer.concat([0, 32].map((at) => coordinate(p.subarray(at, at + 32))));
const g2 = (p) => Buffer.concat([32, 0, 96, 64].map((at) => coordinate(p.subarray(at, at + 32))));

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
// they were made. It parses and hashes the points; snarkjs zkey verify is what checks them.
export function readZkey(path) {
  const fd = openSync(path, "r");
  try {
    const head = readAt(fd, 0, 12, path);
    if (head.toString("latin1", 0, 4) !== "zkey" || head.readUInt32LE(4) !== 1) {
      throw new Error(`${path} is not a version 1 zkey file`);
    }
    const sections = new Map();
    let pos = 12;
    for (let i = head.readUInt32LE(8); i > 0; i--) {
      const h = readAt(fd, pos, 12, path);
      const id = h.readUInt32LE(0);
      const length = Number(h.readBigUInt64LE(4));
      if (sections.has(id)) throw new Error(`${path} repeats section ${id}`);
      sections.set(id, { pos: pos + 12, length });
      pos += 12 + length;
    }
    const section = (id) => {
      const s = sections.get(id);
      if (!s) throw new Error(`${path} has no section ${id}`);
      return readAt(fd, s.pos, s.length, path);
    };

    if (section(1).readUInt32LE(0) !== 1) throw new Error(`${path} is not a Groth16 zkey`);
    const header = cursor(section(2), "zkey header");
    const prime = () => (header.u32() === 32 ? littleEndian(header.take(32)) : 0n);
    if (prime() !== Q || prime() !== R) throw new Error(`${path} is not over BN254`);

    const mpc = cursor(section(10), "zkey contributions");
    const csHash = Buffer.from(mpc.take(64));
    const contributions = [];
    for (let i = mpc.u32(); i > 0; i--) contributions.push(readContribution(mpc));
    if (mpc.left !== 0) throw new Error(`${path} has trailing bytes after its contributions`);
    return { csHash, contributions };
  } finally {
    closeSync(fd);
  }
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
