/**
 * @file    logic4_test.cpp
 * @brief   Unit tests for the Logic4 4-state value model
 * @author  Astatine387
 */

#include "core/logic4.h"

#include <gtest/gtest.h>

#include <array>
#include <sstream>

constexpr std::array<Logic4, 4> kAll = { Logic4::k0, Logic4::k1, Logic4::kX, Logic4::kZ };

/* ==================================================
 * Two-input gate truth tables
 * ================================================== */

TEST(Logic4Gate, And) {
  using enum Logic4;

  EXPECT_EQ(And(k0, k0), k0);
  EXPECT_EQ(And(k0, k1), k0);
  EXPECT_EQ(And(k0, kX), k0);
  EXPECT_EQ(And(k0, kZ), k0);

  EXPECT_EQ(And(k1, k0), k0);
  EXPECT_EQ(And(k1, k1), k1);
  EXPECT_EQ(And(k1, kX), kX);
  EXPECT_EQ(And(k1, kZ), kX);

  EXPECT_EQ(And(kX, k0), k0);
  EXPECT_EQ(And(kX, k1), kX);
  EXPECT_EQ(And(kX, kX), kX);
  EXPECT_EQ(And(kX, kZ), kX);

  EXPECT_EQ(And(kZ, k0), k0);
  EXPECT_EQ(And(kZ, k1), kX);
  EXPECT_EQ(And(kZ, kX), kX);
  EXPECT_EQ(And(kZ, kZ), kX);
}

TEST(Logic4Gate, Or) {
  using enum Logic4;

  EXPECT_EQ(Or(k0, k0), k0);
  EXPECT_EQ(Or(k0, k1), k1);
  EXPECT_EQ(Or(k0, kX), kX);
  EXPECT_EQ(Or(k0, kZ), kX);

  EXPECT_EQ(Or(k1, k0), k1);
  EXPECT_EQ(Or(k1, k1), k1);
  EXPECT_EQ(Or(k1, kX), k1);
  EXPECT_EQ(Or(k1, kZ), k1);

  EXPECT_EQ(Or(kX, k0), kX);
  EXPECT_EQ(Or(kX, k1), k1);
  EXPECT_EQ(Or(kX, kX), kX);
  EXPECT_EQ(Or(kX, kZ), kX);

  EXPECT_EQ(Or(kZ, k0), kX);
  EXPECT_EQ(Or(kZ, k1), k1);
  EXPECT_EQ(Or(kZ, kX), kX);
  EXPECT_EQ(Or(kZ, kZ), kX);
}

TEST(Logic4Gate, Xor) {
  using enum Logic4;

  EXPECT_EQ(Xor(k0, k0), k0);
  EXPECT_EQ(Xor(k0, k1), k1);
  EXPECT_EQ(Xor(k0, kX), kX);
  EXPECT_EQ(Xor(k0, kZ), kX);

  EXPECT_EQ(Xor(k1, k0), k1);
  EXPECT_EQ(Xor(k1, k1), k0);
  EXPECT_EQ(Xor(k1, kX), kX);
  EXPECT_EQ(Xor(k1, kZ), kX);

  EXPECT_EQ(Xor(kX, k0), kX);
  EXPECT_EQ(Xor(kX, k1), kX);
  EXPECT_EQ(Xor(kX, kX), kX);
  EXPECT_EQ(Xor(kX, kZ), kX);

  EXPECT_EQ(Xor(kZ, k0), kX);
  EXPECT_EQ(Xor(kZ, k1), kX);
  EXPECT_EQ(Xor(kZ, kX), kX);
  EXPECT_EQ(Xor(kZ, kZ), kX);
}

/* ==================================================
 * One-input gates
 * ================================================== */

TEST(Logic4Gate, Not) {
  using enum Logic4;

  EXPECT_EQ(Not(k0), k1);
  EXPECT_EQ(Not(k1), k0);
  EXPECT_EQ(Not(kX), kX);
  EXPECT_EQ(Not(kZ), kX);
}

TEST(Logic4Gate, Buf) {
  using enum Logic4;

  EXPECT_EQ(Buf(k0), k0);
  EXPECT_EQ(Buf(k1), k1);
  EXPECT_EQ(Buf(kX), kX);
  EXPECT_EQ(Buf(kZ), kX);
}

/* ==================================================
 * Inverting gates (NAND/NOR/XNOR invert AND/OR/XOR)
 * ================================================== */

TEST(Logic4Gate, NandIsInvertedAnd) {
  using enum Logic4;

  for (Logic4 a : kAll) {
    for (Logic4 b : kAll) {
      EXPECT_EQ(Nand(a, b), Not(And(a, b)));
    }
  }

  EXPECT_EQ(Nand(k0, k0), k1);
  EXPECT_EQ(Nand(k1, k1), k0);
  EXPECT_EQ(Nand(k1, kZ), kX);
}

TEST(Logic4Gate, NorIsInvertedOr) {
  using enum Logic4;

  for (Logic4 a : kAll) {
    for (Logic4 b : kAll) {
      EXPECT_EQ(Nor(a, b), Not(Or(a, b)));
    }
  }

  EXPECT_EQ(Nor(k0, k0), k1);
  EXPECT_EQ(Nor(k1, k0), k0);
  EXPECT_EQ(Nor(k0, kZ), kX);
}

TEST(Logic4Gate, XnorIsInvertedXor) {
  using enum Logic4;

  for (Logic4 a : kAll) {
    for (Logic4 b : kAll) {
      EXPECT_EQ(Xnor(a, b), Not(Xor(a, b)));
    }
  }

  EXPECT_EQ(Xnor(k0, k0), k1);
  EXPECT_EQ(Xnor(k0, k1), k0);
  EXPECT_EQ(Xnor(kX, k0), kX);
}

/* ==================================================
 * Properties
 * ================================================== */

TEST(Logic4Gate, BinaryGatesAreCommutative) {
  for (Logic4 a : kAll) {
    for (Logic4 b : kAll) {
      EXPECT_EQ(And(a, b), And(b, a));
      EXPECT_EQ(Or(a, b), Or(b, a));
      EXPECT_EQ(Xor(a, b), Xor(b, a));
    }
  }
}

/* ==================================================
 * Multi-driver resolution
 * ================================================== */

TEST(Logic4Resolve, TruthTable) {
  using enum Logic4;

  EXPECT_EQ(Resolve(k0, k0), k0);
  EXPECT_EQ(Resolve(k0, k1), kX);
  EXPECT_EQ(Resolve(k0, kX), kX);
  EXPECT_EQ(Resolve(k0, kZ), k0);

  EXPECT_EQ(Resolve(k1, k0), kX);
  EXPECT_EQ(Resolve(k1, k1), k1);
  EXPECT_EQ(Resolve(k1, kX), kX);
  EXPECT_EQ(Resolve(k1, kZ), k1);

  EXPECT_EQ(Resolve(kX, k0), kX);
  EXPECT_EQ(Resolve(kX, k1), kX);
  EXPECT_EQ(Resolve(kX, kX), kX);
  EXPECT_EQ(Resolve(kX, kZ), kX);

  EXPECT_EQ(Resolve(kZ, k0), k0);
  EXPECT_EQ(Resolve(kZ, k1), k1);
  EXPECT_EQ(Resolve(kZ, kX), kX);
  EXPECT_EQ(Resolve(kZ, kZ), kZ);
}

TEST(Logic4Resolve, IsCommutative) {
  for (Logic4 a : kAll) {
    for (Logic4 b : kAll) {
      EXPECT_EQ(Resolve(a, b), Resolve(b, a));
    }
  }
}

TEST(Logic4Resolve, HighImpedanceIsIdentity) {
  for (Logic4 v : kAll) {
    EXPECT_EQ(Resolve(Logic4::kZ, v), v);
    EXPECT_EQ(Resolve(v, Logic4::kZ), v);
  }
}

/* ==================================================
 * Character conversion
 * ================================================== */

TEST(Logic4, ToCharMapping) {
  using enum Logic4;

  EXPECT_EQ(ToChar(k0), '0');
  EXPECT_EQ(ToChar(k1), '1');
  EXPECT_EQ(ToChar(kX), 'x');
  EXPECT_EQ(ToChar(kZ), 'z');
}

TEST(Logic4, StreamOperator) {
  using enum Logic4;

  std::ostringstream oss;

  oss << k0 << k1 << kX << kZ;

  EXPECT_EQ(oss.str(), "01xz");
}