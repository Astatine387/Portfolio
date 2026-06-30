/**
 * @file    logic4.h
 * @brief   4-state logic value model
 * @author  Astatine387
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <iosfwd>

/**
 * @enum    Logic4
 * @brief   Four-valued logic state of a net
 */
enum class Logic4 : std::uint8_t {
  k0 = 0,
  k1 = 1,
  kX = 2,
  kZ = 3,
};

static_assert(static_cast<std::uint8_t>(Logic4::k0) == 0);
static_assert(static_cast<std::uint8_t>(Logic4::k1) == 1);
static_assert(static_cast<std::uint8_t>(Logic4::kX) == 2);
static_assert(static_cast<std::uint8_t>(Logic4::kZ) == 3);

/**
 * @brief   Two-input AND gate (a Z on an input is treated as X)
 */
[[nodiscard]] constexpr Logic4 And(Logic4 a, Logic4 b) {
  using enum Logic4;

  constexpr std::array<Logic4, 16> kTable = {
    k0, k0, k0, k0,  // a = 0
    k0, k1, kX, kX,  // a = 1
    k0, kX, kX, kX,  // a = X
    k0, kX, kX, kX,  // a = Z
  };

  return kTable[static_cast<std::size_t>(a) * 4 + static_cast<std::size_t>(b)];
}

/**
 * @brief   Two-input OR gate (a Z on an input is treated as X)
 */
[[nodiscard]] constexpr Logic4 Or(Logic4 a, Logic4 b) {
  using enum Logic4;

  constexpr std::array<Logic4, 16> kTable = {
    k0, k1, kX, kX,  // a = 0
    k1, k1, k1, k1,  // a = 1
    kX, k1, kX, kX,  // a = X
    kX, k1, kX, kX,  // a = Z
  };

  return kTable[static_cast<std::size_t>(a) * 4 + static_cast<std::size_t>(b)];
}

/**
 * @brief   Two-input XOR gate (a Z on an input is treated as X)
 */
[[nodiscard]] constexpr Logic4 Xor(Logic4 a, Logic4 b) {
  using enum Logic4;

  constexpr std::array<Logic4, 16> kTable = {
    k0, k1, kX, kX,  // a = 0
    k1, k0, kX, kX,  // a = 1
    kX, kX, kX, kX,  // a = X
    kX, kX, kX, kX,  // a = Z
  };

  return kTable[static_cast<std::size_t>(a) * 4 + static_cast<std::size_t>(b)];
}

/**
 * @brief   One-input NOT gate (a Z on the input is treated as X)
 */
[[nodiscard]] constexpr Logic4 Not(Logic4 a) {
  using enum Logic4;

  constexpr std::array<Logic4, 4> kTable = { k1, k0, kX, kX };

  return kTable[static_cast<std::size_t>(a)];
}

/**
 * @brief   One-input buffer (a Z on the input is treated as X)
 */
[[nodiscard]] constexpr Logic4 Buf(Logic4 a) {
  using enum Logic4;

  constexpr std::array<Logic4, 4> kTable = { k0, k1, kX, kX };

  return kTable[static_cast<std::size_t>(a)];
}

/**
 * @brief   Two-input NAND gate
 */
[[nodiscard]] constexpr Logic4 Nand(Logic4 a, Logic4 b) {
  return Not(And(a, b));
}

/**
 * @brief   Two-input NOR gate
 */
[[nodiscard]] constexpr Logic4 Nor(Logic4 a, Logic4 b) {
  return Not(Or(a, b));
}

/**
 * @brief   Two-input XNOR gate
 */
[[nodiscard]] constexpr Logic4 Xnor(Logic4 a, Logic4 b) {
  return Not(Xor(a, b));
}

/**
 * @brief   Resolve two drivers on the same net
 */
[[nodiscard]] constexpr Logic4 Resolve(Logic4 a, Logic4 b) {
  using enum Logic4;

  constexpr std::array<Logic4, 16> kTable = {
    k0, kX, kX, k0,  // a = 0
    kX, k1, kX, k1,  // a = 1
    kX, kX, kX, kX,  // a = X
    k0, k1, kX, kZ,  // a = Z
  };

  return kTable[static_cast<std::size_t>(a) * 4 + static_cast<std::size_t>(b)];
}

/**
 * @brief   Convert a logic value to its VCD character ('0', '1', 'x', 'z')
 */
[[nodiscard]] constexpr char ToChar(Logic4 v) {
  constexpr std::array<char, 4> kTable = { '0', '1', 'x', 'z' };

  return kTable[static_cast<std::size_t>(v)];
}

/**
 * @brief   Stream a logic value as its VCD character
 */
std::ostream& operator<<(std::ostream& os, Logic4 v);