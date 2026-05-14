/**
 * @file    VaultEntryTest.cpp
 * @brief   Unit tests for Vault entry management functions
 * @author  Astatine387
 */

#include "Core/Vault.h"

#include <gtest/gtest.h>

/**
 * @class   VaultEntryTest
 * @brief   Test fixture for Vault entry CRUD operations
 */
class VaultEntryTest : public ::testing::Test {
 protected:
  Vault vault_;

  /**
   * @brief   Set up test fixture with a master password
   */
  void SetUp() override {
    Password pw;
    const char* pwstr = "password";
    size_t psize = strlen(pwstr);

    pw.SetData(pwstr, psize);

    vault_.SetPW(pw);
  }

  /**
   * @brief   Create a Password object from C-string
   * @param   str     Password string
   * @return  Password object
   */
  Password MakePW(const char* str) {
    Password pw;

    pw.SetData(str, strlen(str));

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
  int res = vault_.CreateEntry("Google", "user@google.com", MakePW("password"));

  EXPECT_EQ(res, 0);
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

  int res = vault_.CreateEntry("Google", "user@google.com", MakePW("asdf1234"));

  EXPECT_EQ(res, 1);
  EXPECT_EQ(vault_.GetEntryCount(), 1);
}

/* ==================================================
 * Update Entry Test
 * ================================================== */

/**
 * @brief   Verify updating an existing entry succeeds
 */
TEST_F(VaultEntryTest, UpdateBasic) {
  vault_.CreateEntry("Google", "old@google.com", MakePW("password"));

  int res = vault_.UpdateEntry("Google", "old@google.com", "Google", "new@google.com",
                               MakePW("asdf1234"));

  EXPECT_EQ(res, 0);
  EXPECT_EQ(vault_.GetEntryCount(), 1);

  /* Verify the updated entry exists */

  const auto& entries = vault_.GetEntries();
  Entry target = { "Google", "new@google.com" };

  auto it = entries.find(target);

  EXPECT_NE(it, entries.end());
}

/**
 * @brief   Verify updating a non-existent entry fails
 */
TEST_F(VaultEntryTest, UpdateNonExistent) {
  int res = vault_.UpdateEntry("Google", "user@google.com", "Google", "user@google.com",
                               MakePW("password"));

  EXPECT_EQ(res, 1);
}

/**
 * @brief   Verify updating to a conflicting entry fails
 */
TEST_F(VaultEntryTest, UpdateConflict) {
  vault_.CreateEntry("Google", "user1@google.com", MakePW("password"));
  vault_.CreateEntry("Google", "user2@google.com", MakePW("asdf1234"));

  int res = vault_.UpdateEntry("Google", "user1@google.com", "Google", "user2@google.com",
                               MakePW("qwerty"));

  EXPECT_EQ(res, 2);
  EXPECT_EQ(vault_.GetEntryCount(), 2);
}

/**
 * @brief   Verify updating entry to same key with different password succeeds
 */
TEST_F(VaultEntryTest, UpdateSameKeySelf) {
  vault_.CreateEntry("Google", "user@google.com", MakePW("password"));

  int res = vault_.UpdateEntry("Google", "user@google.com", "Google", "user@google.com",
                               MakePW("asdf1234"));

  EXPECT_EQ(res, 0);
  EXPECT_EQ(vault_.GetEntryCount(), 1);
}

/* ==================================================
 * Delete Entry Test
 * ================================================== */

/**
 * @brief   Verify deleting an existing entry succeeds
 */
TEST_F(VaultEntryTest, DeleteBasic) {
  vault_.CreateEntry("Google", "user@google.com", MakePW("password"));

  int res = vault_.DeleteEntry("Google", "user@google.com");

  EXPECT_EQ(res, 0);
  EXPECT_EQ(vault_.GetEntryCount(), 0);
}

/**
 * @brief   Verify deleting a non-existent entry fails
 */
TEST_F(VaultEntryTest, DeleteNonExistent) {
  int res = vault_.DeleteEntry("Google", "user@google.com");

  EXPECT_EQ(res, 1);
}

/**
 * @brief   Verify deleting one entry does not affect others
 */
TEST_F(VaultEntryTest, DeletePreservesOthers) {
  vault_.CreateEntry("Google", "user1@google.com", MakePW("password"));
  vault_.CreateEntry("Microsoft", "user2@microsoft.com", MakePW("asdf1234"));

  vault_.DeleteEntry("Google", "user1@google.com");

  EXPECT_EQ(vault_.GetEntryCount(), 1);

  const auto& entries = vault_.GetEntries();
  Entry target = { "Microsoft", "user2@microsoft.com" };

  EXPECT_NE(entries.find(target), entries.end());
}

/* ==================================================
 * Accessor Test
 * ================================================== */

/**
 * @brief   Verify getEntries returns correct data
 */
TEST_F(VaultEntryTest, GetEntries) {
  vault_.CreateEntry("Google", "user1@google.com", MakePW("password"));
  vault_.CreateEntry("Microsoft", "user2@microsoft.com", MakePW("asdf1234"));
  vault_.CreateEntry("Amazon", "user3@amazon.com", MakePW("qwerty"));

  const auto& entries = vault_.GetEntries();

  EXPECT_EQ(entries.size(), 3);

  /* Entries are ordered by EntryCmp */

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

/* ==================================================
 * Password Verification Test
 * ================================================== */

/**
 * @brief   Verify correct master password passes verification
 */
TEST_F(VaultEntryTest, VerifyPWCorrect) {
  Password pw;
  const char* pwstr = "password";
  size_t psize = strlen(pwstr);

  pw.SetData(pwstr, psize);

  EXPECT_TRUE(vault_.VerifyPW(pw));
}

/**
 * @brief   Verify wrong master password fails verification
 */
TEST_F(VaultEntryTest, VerifyPWWrong) {
  Password pw;
  const char* pwstr = "asdf1234";
  size_t psize = strlen(pwstr);

  pw.SetData(pwstr, psize);

  EXPECT_FALSE(vault_.VerifyPW(pw));
}

/* ==================================================
 * Close Vault Test
 * ================================================== */

/**
 * @brief   Verify closeVault clears all entries and password
 */
TEST_F(VaultEntryTest, CloseVault) {
  vault_.CreateEntry("Google", "user1@google.com", MakePW("password"));
  vault_.CreateEntry("Microsoft", "user2@microsoft.com", MakePW("asdf1234"));

  vault_.CloseVault();

  EXPECT_EQ(vault_.GetEntryCount(), 0);

  Password pw;

  EXPECT_TRUE(vault_.VerifyPW(pw));
}