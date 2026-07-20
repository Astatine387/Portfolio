/**
 * @file    secure_key_test.cpp
 * @brief   Unit tests for SecureKey and DeriveKey
 * @author  Astatine387
 */

#include "core/secure_key.h"

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <type_traits>
#include <utility>

#include "common/constants.h"

/* ==================================================
 * Type Property Tests
 * ================================================== */

/* SecureKey is move-only and can only be minted through DeriveKey */

static_assert(!std::is_copy_constructible_v<SecureKey>);
static_assert(!std::is_copy_assignable_v<SecureKey>);
static_assert(std::is_move_constructible_v<SecureKey>);
static_assert(std::is_move_assignable_v<SecureKey>);
static_assert(!std::is_default_constructible_v<SecureKey>);
static_assert(!std::is_constructible_v<SecureKey, uint8_t*>);

namespace {

/* Small Argon2id parameters keep the derivation tests fast */

KdfParams FastParams() {
  return KdfParams{ .time_cost = 1, .mem_cost = 8, .parallelism = 1 };
}

std::array<uint8_t, kSaltSize> MakeSalt(uint8_t fill) {
  std::array<uint8_t, kSaltSize> salt{};
  salt.fill(fill);
  return salt;
}

/* Derive a key, failing the test if derivation unexpectedly fails */

SecureKey Derive(const std::string& pw, const std::array<uint8_t, kSaltSize>& salt) {
  auto key = DeriveKey(std::span<const char>(pw.data(), pw.size()), salt, FastParams());
  EXPECT_TRUE(key.has_value());
  return std::move(key.value());  // NOLINT(bugprone-unchecked-optional-access)
}

}  // namespace

/* ==================================================
 * Derivation Tests
 * ================================================== */

/**
 * @brief   Verify key derivation succeeds and exposes the key length
 */
TEST(SecureKeyTest, DeriveSucceeds) {
  std::string pw = "password";
  auto salt = MakeSalt(0x01);
  auto key = DeriveKey(std::span<const char>(pw.data(), pw.size()), salt, FastParams());

  ASSERT_TRUE(key.has_value());
  EXPECT_EQ(key->Bytes().size(), kKeySize);  // NOLINT(bugprone-unchecked-optional-access)
}

/**
 * @brief   Verify the same password and salt derive equal keys
 */
TEST(SecureKeyTest, DeterministicForSameInput) {
  SecureKey k0 = Derive("password", MakeSalt(0x01));
  SecureKey k1 = Derive("password", MakeSalt(0x01));

  EXPECT_TRUE(k0.ConstantTimeEquals(k1));
}

/**
 * @brief   Verify different salts derive different keys
 */
TEST(SecureKeyTest, DifferentSaltDiffersKey) {
  SecureKey k0 = Derive("password", MakeSalt(0x01));
  SecureKey k1 = Derive("password", MakeSalt(0x02));

  EXPECT_FALSE(k0.ConstantTimeEquals(k1));
}

/**
 * @brief   Verify different passwords derive different keys
 */
TEST(SecureKeyTest, DifferentPasswordDiffersKey) {
  auto salt = MakeSalt(0x01);
  SecureKey k0 = Derive("password", salt);
  SecureKey k1 = Derive("asdf1234", salt);

  EXPECT_FALSE(k0.ConstantTimeEquals(k1));
}

/* ==================================================
 * Move Semantics Test
 * ================================================== */

/**
 * @brief   Verify move transfers the derived key intact
 */
TEST(SecureKeyTest, MoveTransfersKey) {
  auto salt = MakeSalt(0x01);
  SecureKey src = Derive("password", salt);
  SecureKey ref = Derive("password", salt);

  SecureKey moved = std::move(src);

  EXPECT_TRUE(moved.ConstantTimeEquals(ref));
}
