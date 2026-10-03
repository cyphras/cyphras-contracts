import { F1Field } from "ffjavascript";
import { BASE8, GENERATOR, IDENTITY, L, P, add, mul } from "../reference/babyjub.mjs";
import { addressAt } from "../reference/keys.mjs";
import { LEVELS, MerkleTree } from "../reference/notes.mjs";
import {
  MAX_VALUE,
  alice,
  bob,
  dummy,
  note,
  populatedTree,
  scenario,
  shield,
  spend,
  transactionInput,
  transfer,
  twoInputs,
} from "./fixtures.mjs";
import { randomField } from "./helpers.mjs";

export const FL = new F1Field(L);
export const randomScalar = () => randomField() % L;

// Torsion points of orders 8, 4 and 2.
export const T8 = mul(GENERATOR, L);
export const T4 = add(T8, T8);
export const T2 = add(T4, T4);

// A real input whose note sits in the tree under whatever (gd, pkd) the prover chose.
export function spendOfCommitted({ value, gd, q, pkd }) {
  const n = { value, gd, pkd, rcm: randomField() };
  const tree = populatedTree([[4n, n]]);
  const s = spend(alice, { ...n, q }, 4n, tree.path(4n));
  const outputs = [note(value, bob.address), note(0n, alice.address)];
  return transactionInput(scenario([s, dummy(alice)], outputs, 0n, tree));
}

function transferWith(changes) {
  const s = transfer();
  Object.assign(s.spends[0], changes);
  return transactionInput(s);
}

// A note owned under gd, which the prover tries to spend with the cofactor witness q.
const committedTo = (gd, q) =>
  spendOfCommitted({ value: 10n, gd, q, pkd: mul(gd, alice.keys.ivk) });

// Inputs the circuit must refuse, each case a list of attempts.
export const REJECTED = {
  "a wrong ask": () => [transferWith({ ask: randomScalar() })],

  "a wrong nsk": () => [transferWith({ nsk: randomScalar() })],

  "a non-canonical ask or nsk, although it names the same point": () => [
    transferWith({ ask: alice.keys.ask + L }),
    transferWith({ nsk: alice.keys.nsk + L }),
  ],

  "a gd that is not 8 * q": () => [transferWith({ q: bob.address.q })],

  "a gd at the identity, on a real note or a dummy": () => {
    const s = shield();
    Object.assign(s.spends[1], { gd: IDENTITY, q: IDENTITY });
    return [committedTo(IDENTITY, T8), transactionInput(s)];
  },

  // With gd of order 8, pkd = ivk * gd depends only on ivk mod 8, so any key would match.
  "a gd of order 2, 4 or 8": () =>
    [T2, T4, T8, mul(T8, 3n)].flatMap((gd) => [committedTo(gd, gd), committedTo(gd, T8)]),

  // Each q below is the near miss: 4q, 2q or q, not 8q, lands on gd.
  "a gd of order 2L, 4L or 8L": () => {
    const r = mul(BASE8, randomScalar());
    return [
      committedTo(add(r, T2), add(mul(r, FL.inv(4n)), T8)),
      committedTo(add(r, T4), add(mul(r, FL.inv(2n)), T8)),
      committedTo(add(r, T8), mul(r, FL.inv(8n))),
    ];
  },

  // If gd were not committed, anyone could spend with gd' = (1 / ivk') * pkd for their own ivk'.
  "a gd swapped for one that maps another key onto the note's pkd": () => {
    const gd = mul(alice.address.pkd, FL.inv(bob.keys.ivk));
    return [transferWith({ ask: bob.keys.ask, nsk: bob.keys.nsk, gd, q: mul(gd, FL.inv(8n)) })];
  },

  "a note whose pkd is not ivk * gd": () => {
    const { gd, q } = alice.address;
    return [spendOfCommitted({ value: 10n, gd, q, pkd: addressAt(alice.keys, 1).pkd })];
  },

  "a wrong rcm or value on an input": () => {
    const s = transfer();
    s.spends[0].value += 1n;
    s.outputs[1].value += 1n;
    return [transferWith({ rcm: randomField() }), transactionInput(s)];
  },

  "a wrong rcm or value on an output": () => {
    const input = transactionInput(transfer());
    const value = [input.outValue[0] + 1n, input.outValue[1]];
    return [
      { ...input, outRcm: [randomField(), input.outRcm[1]] },
      { ...input, outValue: value, publicAmount: 1n },
    ];
  },

  "an output gd or pkd off the curve": () =>
    ["gd", "pkd"].map((key) => {
      const s = transfer();
      s.outputs[0][key] = [1n, 2n];
      return transactionInput(s);
    }),

  "an output value of 2^64": () => [transactionInput(shield(1n << 64n))],

  "an input value of 2^64": () => {
    const s = transfer();
    const n = note(1n << 64n, alice.address);
    const tree = populatedTree([[5n, n]]);
    s.root = tree.root();
    s.spends[0] = spend(alice, n, 5n, tree.path(5n));
    s.outputs = [note(MAX_VALUE, bob.address), note(1n, alice.address)];
    return [transactionInput(s)];
  },

  "output values that wrap the field to balance": () => {
    const s = shield(100n);
    s.outputs = [note(101n, alice.address), note(P - 1n, alice.address)];
    return [transactionInput(s)];
  },

  "a pos other than the note's leaf": () => [transferWith({ pos: 6n })],

  // pos + 2^levels shares the low bits, so the path would verify; without the range check one
  // note would have two nullifiers.
  "a pos of 2^levels or more, even when its low bits match the path": () =>
    [1n << BigInt(LEVELS), 1n << 200n].map((extra) => {
      const s = transfer(5n);
      s.spends[0].pos += extra;
      return transactionInput(s);
    }),

  "a wrong root while value is nonzero": () =>
    [randomField(), new MerkleTree().root()].map((root) => {
      const s = transfer();
      s.root = root;
      return transactionInput(s);
    }),

  "two equal nullifiers": () => {
    const n = note(700_000_000n, alice.address);
    const tree = populatedTree([[3n, n]]);
    const twice = spend(alice, n, 3n, tree.path(3n));
    const outputs = [note(1_400_000_000n, bob.address), note(0n, alice.address)];
    const dummies = shield();
    dummies.spends[1] = { ...dummies.spends[0] };
    return [
      transactionInput(scenario([twice, { ...twice }], outputs, 0n, tree)),
      transactionInput(dummies),
    ];
  },

  "a balance off by one in either direction": () =>
    [1n, -1n].map((delta) => {
      const s = transfer();
      s.publicAmount += delta;
      return transactionInput(s);
    }),

  "swapped nullifiers or output commitments": () => {
    const input = transactionInput(twoInputs());
    return [
      { ...input, nf: [...input.nf].reverse() },
      { ...input, cmOut: [...input.cmOut].reverse() },
    ];
  },
};
