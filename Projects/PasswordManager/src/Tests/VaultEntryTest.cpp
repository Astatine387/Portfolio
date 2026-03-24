/**
 * @file    VaultEntryTest.cpp
 * @brief   Unit tests for Vault entry management functions
 * @author  Astatine387
 */

#include <gtest/gtest.h>
#include "Core/Vault.h"


/**
 * @class   VaultEntryTest
 * @brief   Test fixture for Vault entry CRUD operations
 */
class VaultEntryTest : public::testing::Test {
protected:
    Vault vault;

    /**
     * @brief   Set up test fixture with a master password
     */
    void SetUp() override {
        Password pw;
        const char *pwstr = "password";
        size_t psize = strlen(pwstr);

        pw.setData(pwstr, psize);

        vault.setPW(pw);
    }

    /**
     * @brief   Create a Password object from C-string
     * @param   str     Password string
     * @return  Password object
     */
    Password makePW(const char *str) {
        Password pw;

        pw.setData(str, strlen(str));

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
    int res = vault.createEntry("Google", "user@google.com", makePW("password"));

    EXPECT_EQ(res, 0);
    EXPECT_EQ(vault.getEntryCount(), 1);
}

/**
 * @brief   Verify creating multiple unique entries succeeds
 */
TEST_F(VaultEntryTest, CreateMultiple) {
    vault.createEntry("Google", "user1@google.com", makePW("password"));
    vault.createEntry("Microsoft", "user2@microsoft.com", makePW("asdf1234"));
    vault.createEntry("Amazon", "user3@amazon.com", makePW("qwerty"));

    EXPECT_EQ(vault.getEntryCount(), 3);
}

/**
 * @brief   Verify creating a duplicate entry fails
 */
TEST_F(VaultEntryTest, CreateDuplicate) {
    vault.createEntry("Google", "user@google.com", makePW("password"));

    int res = vault.createEntry("Google", "user@google.com", makePW("asdf1234"));

    EXPECT_EQ(res, 1);
    EXPECT_EQ(vault.getEntryCount(), 1);
}


/* ==================================================
 * Update Entry Test
 * ================================================== */

/**
 * @brief   Verify updating an existing entry succeeds
 */
TEST_F(VaultEntryTest, UpdateBasic) {
    vault.createEntry("Google", "old@google.com", makePW("password"));

    int res = vault.updateEntry("Google", "old@google.com", "Google", "new@google.com", makePW("asdf1234"));

    EXPECT_EQ(res, 0);
    EXPECT_EQ(vault.getEntryCount(), 1);


    /* Verify the updated entry exists */

    const auto &entries = vault.getEntries();
    Entry target = { "Google", "new@google.com" };

    auto it = entries.find(target);

    EXPECT_NE(it, entries.end());
}

/**
 * @brief   Verify updating a non-existent entry fails
 */
TEST_F(VaultEntryTest, UpdateNonExistent) {
    int res = vault.updateEntry("Google", "user@google.com", "Google", "user@google.com", makePW("password"));

    EXPECT_EQ(res, 1);
}

/**
 * @brief   Verify updating to a conflicting entry fails
 */
TEST_F(VaultEntryTest, UpdateConflict) {
    vault.createEntry("Google", "user1@google.com", makePW("password"));
    vault.createEntry("Google", "user2@google.com", makePW("asdf1234"));

    int res = vault.updateEntry("Google", "user1@google.com", "Google", "user2@google.com", makePW("qwerty"));

    EXPECT_EQ(res, 2);
    EXPECT_EQ(vault.getEntryCount(), 2);
}

/**
 * @brief   Verify updating entry to same key with different password succeeds
 */
TEST_F(VaultEntryTest, UpdateSameKeySelf) {
    vault.createEntry("Google", "user@google.com", makePW("password"));
    
    int res = vault.updateEntry("Google", "user@google.com", "Google", "user@google.com", makePW("asdf1234"));

    EXPECT_EQ(res, 0);
    EXPECT_EQ(vault.getEntryCount(), 1);
}


/* ==================================================
 * Delete Entry Test
 * ================================================== */

/**
 * @brief   Verify deleting an existing entry succeeds
 */
TEST_F(VaultEntryTest, DeleteBasic) {
    vault.createEntry("Google", "user@google.com", makePW("password"));

    int res = vault.deleteEntry("Google", "user@google.com");

    EXPECT_EQ(res, 0);
    EXPECT_EQ(vault.getEntryCount(), 0);
}

/**
 * @brief   Verify deleting a non-existent entry fails
 */
TEST_F(VaultEntryTest, DeleteNonExistent) {
    int res = vault.deleteEntry("Google", "user@google.com");

    EXPECT_EQ(res, 1);
}

/**
 * @brief   Verify deleting one entry does not affect others
 */
TEST_F(VaultEntryTest, DeletePreservesOthers) {
    vault.createEntry("Google", "user1@google.com", makePW("password"));
    vault.createEntry("Microsoft", "user2@microsoft.com", makePW("asdf1234"));

    vault.deleteEntry("Google", "user1@google.com");

    EXPECT_EQ(vault.getEntryCount(), 1);

    const auto &entries = vault.getEntries();
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
    vault.createEntry("Google", "user1@google.com", makePW("password"));
    vault.createEntry("Microsoft", "user2@microsoft.com", makePW("asdf1234"));
    vault.createEntry("Amazon", "user3@amazon.com", makePW("qwerty"));

    const auto &entries = vault.getEntries();

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
    EXPECT_EQ(vault.getEntryCount(), 0);

    vault.createEntry("Google", "user1@google.com", makePW("password"));

    EXPECT_EQ(vault.getEntryCount(), 1);

    vault.createEntry("Microsoft", "user2@microsoft.com", makePW("asdf1234"));

    EXPECT_EQ(vault.getEntryCount(), 2);

    vault.deleteEntry("Google", "user1@google.com");

    EXPECT_EQ(vault.getEntryCount(), 1);
}


/* ==================================================
 * Password Verification Test
 * ================================================== */

/**
 * @brief   Verify correct master password passes verification
 */
TEST_F(VaultEntryTest, VerifyPWCorrect) {
    Password pw;
    const char *pwstr = "password";
    size_t psize = strlen(pwstr);

    pw.setData(pwstr, psize);

    EXPECT_TRUE(vault.verifyPW(pw));
}

/**
 * @brief   Verify wrong master password fails verification
 */
TEST_F(VaultEntryTest, VerifyPWWrong) {
    Password pw;
    const char *pwstr = "asdf1234";
    size_t psize = strlen(pwstr);

    pw.setData(pwstr, psize);

    EXPECT_FALSE(vault.verifyPW(pw));
}


/* ==================================================
 * Close Vault Test
 * ================================================== */

/**
 * @brief   Verify closeVault clears all entries and password
 */
TEST_F(VaultEntryTest, CloseVault) {
    vault.createEntry("Google", "user1@google.com", makePW("password"));
    vault.createEntry("Microsoft", "user2@microsoft.com", makePW("asdf1234"));

    vault.closeVault();

    EXPECT_EQ(vault.getEntryCount(), 0);

    Password pw;

    EXPECT_TRUE(vault.verifyPW(pw));
}