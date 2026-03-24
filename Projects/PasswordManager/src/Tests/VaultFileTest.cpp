/**
 * @file    VaultFileTest.cpp
 * @brief   Unit tests for Vault file management functions
 * @author  Astatine387
 */

#include "Core/Vault.h"
#include "Utils/library.h"
#include <gtest/gtest.h>


/**
 * @class   VaultFileTest
 * @brief   Test fixture for Vault file operations
 */
class VaultFileTest : public::testing::Test {
protected:
    Vault vault;
    QString path = "test.vault";

    /**
     * @brief   Set up test fixture with master password and empty vault file
     */
    void SetUp() override {
        Password pw;
        const char *pwstr = "password";
        size_t psize = strlen(pwstr);

        pw.setData(pwstr, psize);

        vault.setPW(pw);
        vault.newVault(path);
    }

    /**
     * @brief   Clean up temporary vault files after each test
     */
    void TearDown() override {
        RemoveFile(path);
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

    /**
     * @brief   Close vault and reopen with master password
     * @return  0 on success, non-zero on failure
     */
    int reload() {
        const char *pwstr = "password";
        size_t psize = strlen(pwstr);

        return reload(pwstr, psize);
    }

    /**
     * @brief   Close vault and reopen with specified password
     * @param   pwStr   Password string
     * @param   pwLen   Password length
     * @return  0 on success, non-zero on failure
     */
    int reload(const char *pwStr, size_t pwLen) {
        vault.closeVault();

        Password pw;

        pw.setData(pwStr, pwLen);
        vault.setPW(pw);

        return vault.openVault(path);
    }
};


/* ==================================================
 * New Vault Test
 * ================================================== */

/**
 * @brief   Verify creating a new vault file succeeds
 */
TEST_F(VaultFileTest, NewVault) {
    EXPECT_TRUE(FileExists(path));
}

/**
 * @brief   Verify new vault can be opened and is empty
 */
TEST_F(VaultFileTest, NewVaultIsEmpty) {
    EXPECT_EQ(reload(), 0);
    EXPECT_EQ(vault.getEntryCount(), 0);
}


/* ==================================================
 * Open Vault Test
 * ================================================== */

/**
 * @brief   Verify opening vault with wrong password fails
 */
TEST_F(VaultFileTest, OpenWrongPassword) {
    const char *pwstr = "asdf1234";
    size_t psize = strlen(pwstr);

    EXPECT_NE(reload(pwstr, psize), 0);
}

/**
 * @brief   Verify opening non-existent vault fails
 */
TEST_F(VaultFileTest, OpenNonExistent) {
    vault.closeVault();

    Password pw;

    const char *pwstr = "asdf1234";
    size_t psize = strlen(pwstr);

    pw.setData(pwstr, psize);
    vault.setPW(pw);

    EXPECT_NE(vault.openVault("nonexistent.vault"), 0);
}

/**
 * @brief   Verify opening a file with invalid magic number fails
 */
TEST_F(VaultFileTest, OpenCorruptedFile) {
    FILE *file = nullptr;
    std::vector<uint8_t> vec(kMinSize, 0x00);

    OpenFile(&file, path, "wb");

    if (file) {
        fwrite(vec.data(), sizeof(uint8_t), vec.size(), file);
        fclose(file);
    }

    EXPECT_NE(reload(), 0);
}

/**
 * @brief   Verify opening an empty file fails
 */
TEST_F(VaultFileTest, OpenEmptyFile) {
    FILE *file = nullptr;

    OpenFile(&file, path, "wb");

    if (file) fclose(file);

    EXPECT_NE(reload(), 0);
}

/**
 * @brief   Verify opening a file smaller than minimum vault size fails
 */
TEST_F(VaultFileTest, OpenUndersizedFile) {
    FILE *file = nullptr;
    std::vector<uint8_t> vec(kMinSize - 1, 0x00);

    OpenFile(&file, path, "wb");

    if (file) {
        fwrite(vec.data(), sizeof(uint8_t), vec.size(), file);
        fclose(file);
    }

    EXPECT_NE(reload(), 0);
}

/**
 * @brief   Verify opening a file exceeding maximum size fails
 */
TEST_F(VaultFileTest, OpenOversizedFile) {
    FILE *file = nullptr;

    OpenFile(&file, path, "wb");

    if (file) {
    #ifdef _WIN32
        _fseeki64(file, kMaxSize + 1, SEEK_SET);

    #else
        fseeko(file, kMaxSize + 1, SEEK_SET);

    #endif

        fputc(0, file);
        fclose(file);
    }

    EXPECT_NE(reload(), 0);
}

/**
 * @brief   Verify opening a vault where entry count grossly exceeds available data fails
 */
TEST_F(VaultFileTest, OpenInflatedEntryCount) {
    AES_GCM aes;
    const char *pwstr = "password";
    size_t psize = strlen(pwstr);


    /* Entry count is 10, but there is no actual entries */

    uint32_t entryCnt = 10;
    size_t srcSize = sizeof(uint32_t);

    std::vector<uint8_t> src(srcSize);

    memcpy(src.data(), &entryCnt, sizeof(uint32_t));


    /* Encrypt */

    size_t encSize = kSaltSize + kIVSize + srcSize + kTagSize;

    std::vector<uint8_t> enc(encSize);

    aes.encrypt(src.data(), enc.data(), srcSize, pwstr, psize);


    /* Write vault file */

    FILE *file = nullptr;
    uint32_t magic = kMagicNum;

    OpenFile(&file, path, "wb");

    if (file) {
        fwrite(&magic, sizeof(uint32_t), 1, file);
        fwrite(enc.data(), sizeof(uint8_t), encSize, file);
        fclose(file);
    }

    EXPECT_NE(reload(), 0);
}

/**
 * @brief   Verify opening a vault where entry count exceeds actual entries fails during deserialization
 */
TEST_F(VaultFileTest, OpenPartialEntryData) {
    AES_GCM aes;
    const char *pwstr = "password";
    size_t psize = strlen(pwstr);


    /* Entry count is 2, but only 1 entry is valid */

    Entry entry;

    entry.site = "Google";
    entry.acc = "user@google.com";
    entry.pw.setData("password", 8);

    uint32_t entryCnt = 2;
    size_t entrySize = entry.size();
    size_t srcSize = sizeof(uint32_t) + entrySize + kMinEntrySize;

    std::vector<uint8_t> src(srcSize, 0xFF);

    size_t cur = 0;

    memcpy(src.data() + cur, &entryCnt, sizeof(uint32_t));
    cur += sizeof(uint32_t);

    entry.ser(src.data() + cur);


    /* Encrypt */

    size_t encSize = kSaltSize + kIVSize + srcSize + kTagSize;

    std::vector<uint8_t> enc(encSize);

    aes.encrypt(src.data(), enc.data(), srcSize, pwstr, psize);


    /* Write vault file */

    FILE *file = nullptr;
    uint32_t magic = kMagicNum;

    OpenFile(&file, path, "wb");

    if (file) {
        fwrite(&magic, sizeof(uint32_t), 1, file);
        fwrite(enc.data(), sizeof(uint8_t), encSize, file);
        fclose(file);
    }

    EXPECT_NE(reload(), 0);
}


/* ==================================================
 * Save and Reload Test
 * ================================================== */

/**
 * @brief   Verify entries survive save and reload cycle
 */
TEST_F(VaultFileTest, SaveAndReload) {
    vault.createEntry("Google", "user1@google.com", makePW("password"));
    vault.createEntry("Microsoft", "user2@microsoft.com", makePW("asdf1234"));
    vault.saveVault(path);

    EXPECT_EQ(reload(), 0);
    EXPECT_EQ(vault.getEntryCount(), 2);

    const auto &entries = vault.getEntries();

    EXPECT_NE(entries.find({ "Google", "user1@google.com" }), entries.end());
    EXPECT_NE(entries.find({ "Microsoft", "user2@microsoft.com" }), entries.end());
}

/**
 * @brief   Verify passwords are correctly preserved through save and reload
 */
TEST_F(VaultFileTest, SavePreservesPasswords) {
    Password pw = makePW("password");

    vault.createEntry("Google", "user@google.com", pw);
    vault.saveVault(path);

    EXPECT_EQ(reload(), 0);

    const auto &entries = vault.getEntries();

    EXPECT_TRUE(entries.begin()->pw.equal(pw));
}

/**
 * @brief   Verify saving an empty vault and reopening it succeeds
 */
TEST_F(VaultFileTest, SaveEmptyVault) {
    vault.saveVault(path);

    EXPECT_EQ(reload(), 0);
    EXPECT_EQ(vault.getEntryCount(), 0);
}


/* ==================================================
 * Change Password Test
 * ================================================== */

/**
 * @brief   Verify changing master password and reopening with new password succeeds
 */
TEST_F(VaultFileTest, ChangePW) {
    const char *pwstr = "asdf1234";
    size_t psize = strlen(pwstr);

    vault.createEntry("Google", "user@google.com", makePW("password"));

    EXPECT_EQ(vault.changePW(makePW(pwstr), path), 0);
    EXPECT_EQ(reload(pwstr, psize), 0);
    EXPECT_EQ(vault.getEntryCount(), 1);
}

/**
 * @brief   Verify old password fails after password change
 */
TEST_F(VaultFileTest, ChangePWOldFails) {
    const char *pwstr = "password"; // original master password
    size_t psize = strlen(pwstr);

    vault.changePW(makePW("asdf1234"), path);

    EXPECT_NE(reload(pwstr, psize), 0);
}


/* ==================================================
 * Error Callback Test
 * ================================================== */

/**
 * @brief   Verify error callback is invoked on failure
 */
TEST_F(VaultFileTest, ErrorCallback) {
    bool cb = false;

    vault.setErrorCb([&](const char *msg) {
        cb = true;
    });

    vault.closeVault();
    vault.openVault("nonexistent.vault");

    EXPECT_TRUE(cb);
}

/**
 * @brief   Verify getLastError returns error message on failure
 */
TEST_F(VaultFileTest, GetLastError) {
    vault.closeVault();

    vault.openVault("nonexistent.vault");

    EXPECT_FALSE(vault.getLastError().empty());
}