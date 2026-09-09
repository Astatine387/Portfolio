/**
 * @file    secure_key_test.cpp
 * @brief   Unit tests for SecureKey and DeriveKey
 * @author  Astatine387
 */

#include "core/secure_key.h"

#include <gtest/gtest.h>

#include <algorithm>
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

/**
 * @brief   Verify key derivation succeeds on an empty password
 */
TEST(SecureKeyTest, DeriveEmptyPassword) {
  std::string pw;
  auto salt = MakeSalt(0x01);
  auto key = DeriveKey(std::span<const char>(pw.data(), pw.size()), salt, FastParams());

  EXPECT_TRUE(key.has_value());
}

/**
 * @brief   Verify DeriveKey fails when Argon2id rejects the cost parameters
 */
TEST(SecureKeyTest, DeriveFailsInvalidParams) {
  std::string pw = "password";
  auto salt = MakeSalt(0x01);
  std::span<const char> pw_span(pw.data(), pw.size());

  EXPECT_FALSE(DeriveKey(pw_span, salt, KdfParams{ .time_cost = 0, .mem_cost = 8, .parallelism = 1 }).has_value());
  EXPECT_FALSE(DeriveKey(pw_span, salt, KdfParams{ .time_cost = 1, .mem_cost = 0, .parallelism = 1 }).has_value());
  EXPECT_FALSE(DeriveKey(pw_span, salt, KdfParams{ .time_cost = 1, .mem_cost = 8, .parallelism = 0 }).has_value());
}

/* ==================================================
 * Commitment Tests
 * ================================================== */

/**
 * @brief   Verify a key carries the salt and parameters its derivation consumed
 *
 * What the header is written from, so a key that reported anything else here would describe a derivation other than
 * the one that produced it.
 */
TEST(SecureKeyTest, CarriesSaltAndParams) {
  auto salt = MakeSalt(0x0A);
  SecureKey key = Derive("password", salt);

  EXPECT_TRUE(std::ranges::equal(key.Salt(), salt));
  EXPECT_EQ(key.Params().time_cost, FastParams().time_cost);
  EXPECT_EQ(key.Params().mem_cost, FastParams().mem_cost);
  EXPECT_EQ(key.Params().parallelism, FastParams().parallelism);
}

/**
 * @brief   Verify the same password, salt and parameters commit to the same value
 */
TEST(SecureKeyTest, CommitmentIsDeterministic) {
  SecureKey k0 = Derive("password", MakeSalt(0x01));
  SecureKey k1 = Derive("password", MakeSalt(0x01));

  EXPECT_TRUE(k0.CommitmentMatches(k1.Commitment()));
}

/**
 * @brief   Verify a single character of password changes the commitment
 */
TEST(SecureKeyTest, CommitmentFollowsPassword) {
  auto salt = MakeSalt(0x01);
  SecureKey k0 = Derive("password", salt);
  SecureKey k1 = Derive("passwore", salt);

  EXPECT_FALSE(k0.CommitmentMatches(k1.Commitment()));
}

/**
 * @brief   Verify a different salt changes the commitment
 */
TEST(SecureKeyTest, CommitmentFollowsSalt) {
  SecureKey k0 = Derive("password", MakeSalt(0x01));
  SecureKey k1 = Derive("password", MakeSalt(0x02));

  EXPECT_FALSE(k0.CommitmentMatches(k1.Commitment()));
}

/**
 * @brief   Verify CommitmentMatches accepts the stored value and refuses it one bit later
 */
TEST(SecureKeyTest, CommitmentMatchesOneBitApart) {
  SecureKey key = Derive("password", MakeSalt(0x01));

  std::array<uint8_t, kCommitSize> expected{};

  std::ranges::copy(key.Commitment(), expected.begin());

  EXPECT_TRUE(key.CommitmentMatches(expected));

  expected[0] ^= 0x01;

  EXPECT_FALSE(key.CommitmentMatches(expected));

  expected[0] ^= 0x01;
  expected[kCommitSize - 1] ^= 0x80;

  EXPECT_FALSE(key.CommitmentMatches(expected));
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

/**
 * @brief   Verify move construction carries the commitment, salt and parameters along with the key
 */
TEST(SecureKeyTest, MoveTransfersSaltAndParams) {
  auto salt = MakeSalt(0x07);
  SecureKey src = Derive("password", salt);
  SecureKey ref = Derive("password", salt);

  SecureKey moved = std::move(src);

  EXPECT_TRUE(moved.CommitmentMatches(ref.Commitment()));
  EXPECT_TRUE(std::ranges::equal(moved.Salt(), salt));
  EXPECT_EQ(moved.Params().time_cost, FastParams().time_cost);
  EXPECT_EQ(moved.Params().mem_cost, FastParams().mem_cost);
  EXPECT_EQ(moved.Params().parallelism, FastParams().parallelism);
}

/**
 * @brief   Verify move assignment carries them too
 *
 * The form ChangePW uses to install a new session key, where a key arriving with the previous derivation's salt
 * would be written into the next header.
 */
TEST(SecureKeyTest, MoveAssignmentTransfersSaltAndParams) {
  auto salt = MakeSalt(0x07);
  SecureKey src = Derive("password", salt);
  SecureKey ref = Derive("password", salt);
  SecureKey dst = Derive("asdf1234", MakeSalt(0x08));

  dst = std::move(src);

  EXPECT_TRUE(dst.CommitmentMatches(ref.Commitment()));
  EXPECT_TRUE(std::ranges::equal(dst.Salt(), salt));
}
