/**
 * @file    secure_key_test.cpp
 * @brief   Unit tests for SecureKey and DeriveKey
 * @author  Astatine387
 */

#include "core/secure_key.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <type_traits>
#include <utility>

#include "common/constants.h"

#ifndef _WIN32
#include <sys/resource.h>
#endif

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

/* Small Argon2id parameters keep the derivation tests fast. Well under kMinMemCost, which is allowed
 * because DeriveKey is called directly here: the accepted range is enforced by ValidateHeader, on the
 * parameters a file arrives with, and nothing on this path reads a file. */

KdfParams FastParams() {
  return KdfParams{ .time_cost = 1, .mem_cost = 8, .parallelism = 1 };
}

/* Derive a key, failing the test if derivation unexpectedly fails */

SecureKey Derive(const std::string& pw, const std::array<uint8_t, kSaltSize>& salt) {
  auto key = DeriveKey(std::span<const char>(pw.data(), pw.size()), salt, FastParams());
  EXPECT_TRUE(key.has_value());
  return std::move(key.value());  // NOLINT(bugprone-unchecked-optional-access)
}

std::array<uint8_t, kSaltSize> MakeSalt(uint8_t fill) {
  std::array<uint8_t, kSaltSize> salt{};
  salt.fill(fill);
  return salt;
}

/* Self-move goes through here rather than being written out at the call site. Assigning an object to
 * itself with std::move in plain sight is diagnosed by the compiler, so the two references have to
 * arrive as parameters for the aliasing to be invisible and the code path to be reachable at all. */

void MoveAssign(SecureKey& dst, SecureKey& src) {
  dst = std::move(src);
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
 * @brief   Verify key derivation fails on invalid Argon2id parameters
 */
TEST(SecureKeyTest, DeriveFailsInvalidParams) {
  std::string pw = "password";
  auto salt = MakeSalt(0x01);
  KdfParams params = FastParams();
  params.time_cost = 0;  // Argon2id requires a time cost of at least 1

  auto key = DeriveKey(std::span<const char>(pw.data(), pw.size()), salt, params);

  EXPECT_FALSE(key.has_value());
}

/* ==================================================
 * Commitment Tests
 * ================================================== */

/**
 * @brief   Verify a derivation accepts the commitment it produced
 */
TEST(SecureKeyTest, CommitmentMatchesOwnDerivation) {
  SecureKey key = Derive("password", MakeSalt(0x01));

  EXPECT_EQ(key.Commitment().size(), kCommitSize);
  EXPECT_TRUE(key.CommitmentMatches(key.Commitment()));
}

/**
 * @brief   Verify one flipped bit anywhere in a commitment is enough to reject it
 */
TEST(SecureKeyTest, CommitmentRejectsOneBitChange) {
  SecureKey key = Derive("password", MakeSalt(0x01));

  /* Both ends of the field, because a comparison that stopped short would still accept a change past
   * wherever it stopped */

  const std::array<size_t, 2> positions{ 0, kCommitSize - 1 };

  for (size_t pos : positions) {
    SCOPED_TRACE(testing::Message() << "byte=" << pos);

    std::array<uint8_t, kCommitSize> altered{};

    std::ranges::copy(key.Commitment(), altered.begin());

    altered[pos] ^= 0x01;

    EXPECT_FALSE(key.CommitmentMatches(altered));
  }
}

/**
 * @brief   Verify two passwords over one salt commit to different values
 *
 * This is the property the header commitment rests on: it is what stops a single file from opening
 * under a second password its author chose.
 */
TEST(SecureKeyTest, DifferentPasswordDiffersCommitment) {
  auto salt = MakeSalt(0x01);
  SecureKey k0 = Derive("password", salt);
  SecureKey k1 = Derive("asdf1234", salt);

  EXPECT_FALSE(k0.CommitmentMatches(k1.Commitment()));
  EXPECT_FALSE(k1.CommitmentMatches(k0.Commitment()));
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
 * @brief   Verify move assignment transfers the key and releases the previous one
 */
TEST(SecureKeyTest, MoveAssignTransfersKey) {
  SecureKey src = Derive("password", MakeSalt(0x01));
  SecureKey ref = Derive("password", MakeSalt(0x01));
  SecureKey dst = Derive("asdf1234", MakeSalt(0x02));

  dst = std::move(src);

  EXPECT_TRUE(dst.ConstantTimeEquals(ref));
}

/**
 * @brief   Verify move assignment onto a moved-from key succeeds
 */
TEST(SecureKeyTest, MoveAssignOntoMovedFrom) {
  auto salt = MakeSalt(0x01);
  SecureKey src = Derive("password", salt);
  SecureKey ref = std::move(src);  // src no longer owns a key
  SecureKey tmp = Derive("password", salt);

  src = std::move(tmp);

  EXPECT_TRUE(src.ConstantTimeEquals(ref));
}

/**
 * @brief   Verify self move assignment leaves the key intact
 */
TEST(SecureKeyTest, SelfMoveAssignKeepsKey) {
  auto salt = MakeSalt(0x01);
  SecureKey key = Derive("password", salt);
  SecureKey ref = Derive("password", salt);

  MoveAssign(key, key);

  EXPECT_TRUE(key.ConstantTimeEquals(ref));
}

/* ==================================================
 * Process Hardening Test
 * ================================================== */

#ifndef _WIN32
/**
 * @brief   Verify InitCrypto leaves the process unable to write a core dump
 *
 * The Argon2id working buffer is libargon2's own malloc, so it carries none of the per-allocation
 * exclusion sodium_malloc memory gets and would be written out whole. Refusing the dump is the only
 * thing covering it, so the limit that does the refusing is worth asserting on.
 *
 * Written as a check on the state afterwards rather than on a change, so it holds on a runner whose
 * core limit was already zero before the process started.
 */
TEST(SecureKeyTest, InitCryptoDisablesCoreDumps) {
  InitCrypto();

  rlimit rl = {};

  ASSERT_EQ(getrlimit(RLIMIT_CORE, &rl), 0);
  EXPECT_EQ(rl.rlim_cur, 0U);
}
#endif
