pragma circom 2.2.3;

include "circomlib/circuits/babyjub.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/escalarmulany.circom";

// Order L of the Baby Jubjub prime-order subgroup.
function SUBGROUP_ORDER() {
  return 2736030358979909402780800718157159386076813972158567259200215660948447373041;
}

template AssertNonZero() {
  signal input in;
  signal inv <-- in != 0 ? 1 / in : 0;
  in * inv === 1;
}

// Asserts s < L. BabyPbk alone accepts any 253-bit s, so without this every key would have
// several scalar encodings.
template AssertLtL() {
  signal input s;
  // LessThan(251) is only sound for inputs below 2^251
  component bits = Num2Bits(251);
  bits.in <== s;
  component lt = LessThan(251);
  lt.in[0] <== s;
  lt.in[1] <== SUBGROUP_ORDER();
  lt.out === 1;
}

// Checks in == out + k * L with out < L, k < 8 and no wrap mod p, so (out, k) is unique. As
// 7L < p < 8L, a wrap needs k = 7, where out must therefore stay below p - 7L.
template ReduceModLCheck() {
  signal input in;
  signal input out;
  signal input k;
  var L = SUBGROUP_ORDER();
  var P_MINUS_7L = -7 * L;

  in === out + k * L;

  component outLtL = AssertLtL();
  outLtL.s <== out;

  component kBits = Num2Bits(3);
  kBits.in <== k;

  component kIs7 = IsEqual();
  kIs7.in[0] <== k;
  kIs7.in[1] <== 7;
  component outNoWrap = LessThan(251);
  outNoWrap.in[0] <== out;
  outNoWrap.in[1] <== P_MINUS_7L;
  kIs7.out * (1 - outNoWrap.out) === 0;
}

template ReduceModL() {
  signal input in;
  signal output out;
  out <-- in % SUBGROUP_ORDER();
  signal k <-- in \ SUBGROUP_ORDER();
  component check = ReduceModLCheck();
  check.in <== in;
  check.out <== out;
  check.k <== k;
}

// Asserts p = 8 * q for an on-curve q, and p.x != 0. Clearing the cofactor lands in the
// prime-order subgroup, whose only point with x = 0 is the identity.
template AssertPrimeOrder() {
  signal input p[2];
  signal input q[2];

  component qOnCurve = BabyCheck();
  qOnCurve.x <== q[0];
  qOnCurve.y <== q[1];

  component dbl2 = BabyDbl();
  dbl2.x <== q[0];
  dbl2.y <== q[1];
  component dbl4 = BabyDbl();
  dbl4.x <== dbl2.xout;
  dbl4.y <== dbl2.yout;
  component dbl8 = BabyDbl();
  dbl8.x <== dbl4.xout;
  dbl8.y <== dbl4.yout;
  p[0] === dbl8.xout;
  p[1] === dbl8.yout;

  component notIdentity = AssertNonZero();
  notIdentity.in <== p[0];
}

// EscalarMulAny's incomplete Montgomery formulas have no exceptional case when p has prime
// order and is not the identity, which callers establish with AssertPrimeOrder.
template ScalarMulAny() {
  signal input s;
  signal input p[2];
  signal output out[2];

  component bits = Num2Bits(253);
  bits.in <== s;
  component mul = EscalarMulAny(253);
  mul.e <== bits.out;
  mul.p <== p;
  out <== mul.out;
}
