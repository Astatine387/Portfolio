/**
 * @file    vault_entry_test.cpp
 * @brief   Unit tests for Vault entry management functions
 * @author  Astatine387
 */

#include <gtest/gtest.h>

#include <cstring>

#include "core/vault.h"

/**
 * @class   VaultEntryTest
 * @brief   Test fixture for Vault entry CRUD operations
 *
 * Entry CRUD operates on the in-memory image and does not require an open
 * session key, so the fixture creates entries directly.
 */
class VaultEntryTest : public ::testing::Test {
 protected:
  Vault vault_;

  /**
   * @brief   Create a Password object from C-string
   * @param   str     Password string
   * @return  Password object
   */
  static Password MakePW(const char* str) {
    Password pw;

    EXPECT_EQ(pw.SetData(str, strlen(str)), Result::kSuccess);

    return pw;
  }
};

/* ==================================================
 * Create Entry Test
 * ================================================== */

/**
 * @brief   Verify creating a single entry succeeds
 */
TEST_F(VaultEntryTest, CreateSingle) {
  Result res = vault_.CreateEntry("Google", "user@google.com", MakePW("password"));

  EXPECT_EQ(res, Result::kSuccess);
  EXPECT_EQ(vault_.GetEntryCount(), 1);
}

/**
 * @brief   Verify creating multiple unique entries succeeds
 */
TEST_F(VaultEntryTest, CreateMultiple) {
  vault_.CreateEntry("Google", "user1@google.com", MakePW("password"));
  vault_.CreateEntry("Microsoft", "user2@microsoft.com", MakePW("asdf1234"));
  vault_.CreateEntry("Amazon", "user3@amazon.com", MakePW("qwerty"));

  EXPECT_EQ(vault_.GetEntryCount(), 3);
}

/**
 * @brief   Verify creating a duplicate entry fails
 */
TEST_F(VaultEntryTest, CreateDuplicate) {
  vault_.CreateEntry("Google", "user@google.com", MakePW("password"));

  Result res = vault_.CreateEntry("Google", "user@google.com", MakePW("asdf1234"));

  EXPECT_EQ(res, Result::kFailure);
  EXPECT_EQ(vault_.GetEntryCount(), 1);
}

/**
 * @brief   Verify a created entry's password is stored in the image
 */
TEST_F(VaultEntryTest, CreateStoresPassword) {
  vault_.CreateEntry("Google", "user@google.com", MakePW("s3cr3t!!"));

  Password got;

  EXPECT_TRUE(vault_.GetEntryPW("Google", "user@google.com", got));
  EXPECT_TRUE(got.Equal(MakePW("s3cr3t!!")));
}

/* ==================================================
 * Update Entry Test
 * ================================================== */

/**
 * @brief   Verify updating an existing entry succeeds
 */
TEST_F(VaultEntryTest, UpdateBasic) {
  vault_.CreateEntry("Google", "old@google.com", MakePW("password"));

  UpdateResult res = vault_.UpdateEntry("Google", "old@google.com", "Google", "new@google.com", MakePW("asdf1234"));

  EXPECT_EQ(res, UpdateResult::kSuccess);
  EXPECT_EQ(vault_.GetEntryCount(), 1);

  const auto& entries = vault_.GetEntries();
  Entry target = { .site = "Google", .acc = "new@google.com" };

  EXPECT_NE(entries.find(target), entries.end());
}

/**
 * @brief   Verify updating a non-existent entry fails
 */
TEST_F(VaultEntryTest, UpdateNonExistent) {
  UpdateResult res = vault_.UpdateEntry("Google", "user@google.com", "Google", "user@google.com", MakePW("password"));

  EXPECT_EQ(res, UpdateResult::kNotFound);
}

/**
 * @brief   Verify updating to a conflicting entry fails
 */
TEST_F(VaultEntryTest, UpdateConflict) {
  vault_.CreateEntry("Google", "user1@google.com", MakePW("password"));
  vault_.CreateEntry("Google", "user2@google.com", MakePW("asdf1234"));

  UpdateResult res = vault_.UpdateEntry("Google", "user1@google.com", "Google", "user2@google.com", MakePW("qwerty"));

  EXPECT_EQ(res, UpdateResult::kDuplicate);
  EXPECT_EQ(vault_.GetEntryCount(), 2);
}

/**
 * @brief   Verify updating entry to same key with different password succeeds
 */
TEST_F(VaultEntryTest, UpdateSameKeySelf) {
  vault_.CreateEntry("Google", "user@google.com", MakePW("password"));

  UpdateResult res = vault_.UpdateEntry("Google", "user@google.com", "Google", "user@google.com", MakePW("asdf1234"));

  EXPECT_EQ(res, UpdateResult::kSuccess);
  EXPECT_EQ(vault_.GetEntryCount(), 1);

  Password got;

  EXPECT_TRUE(vault_.GetEntryPW("Google", "user@google.com", got));
  EXPECT_TRUE(got.Equal(MakePW("asdf1234")));
}

/* ==================================================
 * Delete Entry Test
 * ================================================== */

/**
 * @brief   Verify deleting an existing entry succeeds
 */
TEST_F(VaultEntryTest, DeleteBasic) {
  vault_.CreateEntry("Google", "user@google.com", MakePW("password"));

  Result res = vault_.DeleteEntry("Google", "user@google.com");

  EXPECT_EQ(res, Result::kSuccess);
  EXPECT_EQ(vault_.GetEntryCount(), 0);
}

/**
 * @brief   Verify deleting a non-existent entry fails
 */
TEST_F(VaultEntryTest, DeleteNonExistent) {
  Result res = vault_.DeleteEntry("Google", "user@google.com");

  EXPECT_EQ(res, Result::kFailure);
}

/**
 * @brief   Verify deleting one entry preserves the passwords of the others
 */
TEST_F(VaultEntryTest, DeletePreservesOthers) {
  vault_.CreateEntry("Google", "user1@google.com", MakePW("gpass"));
  vault_.CreateEntry("Amazon", "user2@amazon.com", MakePW("apass"));
  vault_.CreateEntry("Microsoft", "user3@microsoft.com", MakePW("mpass"));

  vault_.DeleteEntry("Amazon", "user2@amazon.com");

  EXPECT_EQ(vault_.GetEntryCount(), 2);

  Password google;
  Password microsoft;

  EXPECT_TRUE(vault_.GetEntryPW("Google", "user1@google.com", google));
  EXPECT_TRUE(google.Equal(MakePW("gpass")));
  EXPECT_TRUE(vault_.GetEntryPW("Microsoft", "user3@microsoft.com", microsoft));
  EXPECT_TRUE(microsoft.Equal(MakePW("mpass")));
}

/* ==================================================
 * Accessor Test
 * ================================================== */

/**
 * @brief   Verify getEntries returns correct data in order
 */
TEST_F(VaultEntryTest, GetEntries) {
  vault_.CreateEntry("Google", "user1@google.com", MakePW("password"));
  vault_.CreateEntry("Microsoft", "user2@microsoft.com", MakePW("asdf1234"));
  vault_.CreateEntry("Amazon", "user3@amazon.com", MakePW("qwerty"));

  const auto& entries = vault_.GetEntries();

  EXPECT_EQ(entries.size(), 3);

  auto it = entries.begin();

  EXPECT_EQ(it->site, "Amazon");
  EXPECT_EQ(it->acc, "user3@amazon.com");

  ++it;

  EXPECT_EQ(it->site, "Google");
  EXPECT_EQ(it->acc, "user1@google.com");

  ++it;

  EXPECT_EQ(it->site, "Microsoft");
  EXPECT_EQ(it->acc, "user2@microsoft.com");
}

/**
 * @brief   Verify getEntryCount returns correct count
 */
TEST_F(VaultEntryTest, GetEntryCount) {
  EXPECT_EQ(vault_.GetEntryCount(), 0);

  vault_.CreateEntry("Google", "user1@google.com", MakePW("password"));

  EXPECT_EQ(vault_.GetEntryCount(), 1);

  vault_.CreateEntry("Microsoft", "user2@microsoft.com", MakePW("asdf1234"));

  EXPECT_EQ(vault_.GetEntryCount(), 2);

  vault_.DeleteEntry("Google", "user1@google.com");

  EXPECT_EQ(vault_.GetEntryCount(), 1);
}

/**
 * @brief   Verify getEntryPW fails for a missing entry
 */
TEST_F(VaultEntryTest, GetEntryPWMissing) {
  Password got;

  EXPECT_FALSE(vault_.GetEntryPW("Google", "user@google.com", got));
}

/* ==================================================
 * Close Vault Test
 * ================================================== */

/**
 * @brief   Verify closeVault clears all entries and the session
 */
TEST_F(VaultEntryTest, CloseVault) {
  vault_.CreateEntry("Google", "user1@google.com", MakePW("password"));
  vault_.CreateEntry("Microsoft", "user2@microsoft.com", MakePW("asdf1234"));

  vault_.CloseVault();

  EXPECT_EQ(vault_.GetEntryCount(), 0);
  EXPECT_FALSE(vault_.VerifyPW(MakePW("password")));
}