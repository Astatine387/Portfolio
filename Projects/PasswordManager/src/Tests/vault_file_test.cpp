/**
 * @file    vault_file_test.cpp
 * @brief   Unit tests for Vault file management functions
 * @author  Astatine387
 */

#include <gtest/gtest.h>

#include <cstring>
#include <string>

#include "Core/vault.h"
#include "Utils/platform.h"

/**
 * @class   VaultFileTest
 * @brief   Test fixture for Vault file operations
 */
class VaultFileTest : public ::testing::Test {
 protected:
  Vault vault_;
  std::string path_ = "test.vault";

  /**
   * @brief   Set up test fixture with master password and empty vault file
   */
  void SetUp() override {
    Password pw;
    const char* pwstr = "password";
    size_t psize = strlen(pwstr);

    pw.SetData(pwstr, psize);

    vault_.SetPW(pw);
    vault_.NewVault(path_);
  }

  /**
   * @brief   Clean up temporary vault files after each test
   */
  void TearDown() override { RemoveFile(path_); }

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

  /**
   * @brief   Close vault and reopen with master password
   * @return  kSuccess on success, kFailure on failure
   */
  Result Reload() {
    const char* pwstr = "password";
    size_t psize = strlen(pwstr);

    return Reload(pwstr, psize);
  }

  /**
   * @brief   Close vault and reopen with specified password
   * @param   pwStr   Password string
   * @param   pwLen   Password length
   * @return  kSuccess on success, kFailure on failure
   */
  Result Reload(const char* pw_str, size_t pw_len) {
    vault_.CloseVault();

    Password pw;

    pw.SetData(pw_str, pw_len);
    vault_.SetPW(pw);

    return vault_.OpenVault(path_);
  }
};

/* ==================================================
 * New Vault Test
 * ================================================== */

/**
 * @brief   Verify creating a new vault file succeeds
 */
TEST_F(VaultFileTest, NewVault) {
  EXPECT_TRUE(FileExists(path_));
}

/**
 * @brief   Verify new vault can be opened and is empty
 */
TEST_F(VaultFileTest, NewVaultIsEmpty) {
  EXPECT_EQ(Reload(), Result::kSuccess);
  EXPECT_EQ(vault_.GetEntryCount(), 0);
}

/* ==================================================
 * Open Vault Test
 * ================================================== */

/**
 * @brief   Verify opening vault with wrong password fails
 */
TEST_F(VaultFileTest, OpenWrongPassword) {
  const char* pwstr = "asdf1234";
  size_t psize = strlen(pwstr);

  EXPECT_EQ(Reload(pwstr, psize), Result::kFailure);
}

/**
 * @brief   Verify opening non-existent vault fails
 */
TEST_F(VaultFileTest, OpenNonExistent) {
  vault_.CloseVault();

  Password pw;

  const char* pwstr = "asdf1234";
  size_t psize = strlen(pwstr);

  pw.SetData(pwstr, psize);
  vault_.SetPW(pw);

  EXPECT_EQ(vault_.OpenVault("nonexistent.vault"), Result::kFailure);
}

/**
 * @brief   Verify opening a file with invalid magic number fails
 */
TEST_F(VaultFileTest, OpenCorruptedFile) {
  FILE* file = nullptr;
  std::vector<uint8_t> vec(kMinSize, 0x00);

  OpenFile(&file, path_, "wb");

  if (file) {
    fwrite(vec.data(), sizeof(uint8_t), vec.size(), file);
    fclose(file);
  }

  EXPECT_EQ(Reload(), Result::kFailure);
}

/**
 * @brief   Verify opening an empty file fails
 */
TEST_F(VaultFileTest, OpenEmptyFile) {
  FILE* file = nullptr;

  OpenFile(&file, path_, "wb");

  if (file)
    fclose(file);

  EXPECT_EQ(Reload(), Result::kFailure);
}

/**
 * @brief   Verify opening a file smaller than minimum vault size fails
 */
TEST_F(VaultFileTest, OpenUndersizedFile) {
  FILE* file = nullptr;
  std::vector<uint8_t> vec(kMinSize - 1, 0x00);

  OpenFile(&file, path_, "wb");

  if (file) {
    fwrite(vec.data(), sizeof(uint8_t), vec.size(), file);
    fclose(file);
  }

  EXPECT_EQ(Reload(), Result::kFailure);
}

/**
 * @brief   Verify opening a file exceeding maximum size fails
 */
TEST_F(VaultFileTest, OpenOversizedFile) {
  FILE* file = nullptr;

  OpenFile(&file, path_, "wb");

  if (file) {
#ifdef _WIN32
    _fseeki64(file, kMaxSize + 1, SEEK_SET);

#else
    fseeko(file, kMaxSize + 1, SEEK_SET);

#endif

    fputc(0, file);
    fclose(file);
  }

  EXPECT_EQ(Reload(), Result::kFailure);
}

/**
 * @brief   Verify opening a vault where entry count grossly exceeds available
 * data fails
 */
TEST_F(VaultFileTest, OpenInflatedEntryCount) {
  AesGcm aes;
  const char* pwstr = "password";
  size_t psize = strlen(pwstr);

  /* Entry count is 10, but there is no actual entries */

  uint32_t entry_cnt = 10;
  size_t src_size = sizeof(uint32_t);

  std::vector<uint8_t> src(src_size);

  memcpy(src.data(), &entry_cnt, sizeof(uint32_t));

  /* Encrypt */

  size_t enc_size = kSaltSize + kIVSize + src_size + kTagSize;

  std::vector<uint8_t> enc(enc_size);

  aes.Encrypt(src.data(), enc.data(), src_size, pwstr, psize);

  /* Write vault file */

  FILE* file = nullptr;
  uint32_t magic = kMagicNum;

  OpenFile(&file, path_, "wb");

  if (file) {
    fwrite(&magic, sizeof(uint32_t), 1, file);
    fwrite(enc.data(), sizeof(uint8_t), enc_size, file);
    fclose(file);
  }

  EXPECT_EQ(Reload(), Result::kFailure);
}

/**
 * @brief   Verify opening a vault where entry count exceeds actual entries
 * fails during deserialization
 */
TEST_F(VaultFileTest, OpenPartialEntryData) {
  AesGcm aes;
  const char* pwstr = "password";
  size_t psize = strlen(pwstr);

  /* Entry count is 2, but only 1 entry is valid */

  Entry entry;

  entry.site = "Google";
  entry.acc = "user@google.com";
  entry.pw.SetData("password", 8);

  uint32_t entry_cnt = 2;
  size_t entry_size = entry.Size();
  size_t src_size = sizeof(uint32_t) + entry_size + kMinEntrySize;

  std::vector<uint8_t> src(src_size, 0xFF);

  size_t cur = 0;

  memcpy(src.data() + cur, &entry_cnt, sizeof(uint32_t));
  cur += sizeof(uint32_t);

  entry.Ser(src.data() + cur);

  /* Encrypt */

  size_t enc_size = kSaltSize + kIVSize + src_size + kTagSize;

  std::vector<uint8_t> enc(enc_size);

  aes.Encrypt(src.data(), enc.data(), src_size, pwstr, psize);

  /* Write vault file */

  FILE* file = nullptr;
  uint32_t magic = kMagicNum;

  OpenFile(&file, path_, "wb");

  if (file) {
    fwrite(&magic, sizeof(uint32_t), 1, file);
    fwrite(enc.data(), sizeof(uint8_t), enc_size, file);
    fclose(file);
  }

  EXPECT_EQ(Reload(), Result::kFailure);
}

/* ==================================================
 * Save and Reload Test
 * ================================================== */

/**
 * @brief   Verify entries survive save and reload cycle
 */
TEST_F(VaultFileTest, SaveAndReload) {
  vault_.CreateEntry("Google", "user1@google.com", MakePW("password"));
  vault_.CreateEntry("Microsoft", "user2@microsoft.com", MakePW("asdf1234"));
  vault_.SaveVault(path_);

  EXPECT_EQ(Reload(), Result::kSuccess);
  EXPECT_EQ(vault_.GetEntryCount(), 2);

  const auto& entries = vault_.GetEntries();

  EXPECT_NE(entries.find({ "Google", "user1@google.com" }), entries.end());
  EXPECT_NE(entries.find({ "Microsoft", "user2@microsoft.com" }), entries.end());
}

/**
 * @brief   Verify passwords are correctly preserved through save and reload
 */
TEST_F(VaultFileTest, SavePreservesPasswords) {
  Password pw = MakePW("password");

  vault_.CreateEntry("Google", "user@google.com", pw);
  vault_.SaveVault(path_);

  EXPECT_EQ(Reload(), Result::kSuccess);

  const auto& entries = vault_.GetEntries();

  EXPECT_TRUE(entries.begin()->pw.Equal(pw));
}

/**
 * @brief   Verify saving an empty vault and reopening it succeeds
 */
TEST_F(VaultFileTest, SaveEmptyVault) {
  vault_.SaveVault(path_);

  EXPECT_EQ(Reload(), Result::kSuccess);
  EXPECT_EQ(vault_.GetEntryCount(), 0);
}

/* ==================================================
 * Change Password Test
 * ================================================== */

/**
 * @brief   Verify changing master password and reopening with new password
 * succeeds
 */
TEST_F(VaultFileTest, ChangePW) {
  const char* pwstr = "asdf1234";
  size_t psize = strlen(pwstr);

  vault_.CreateEntry("Google", "user@google.com", MakePW("password"));

  EXPECT_EQ(vault_.ChangePW(MakePW(pwstr), path_), Result::kSuccess);
  EXPECT_EQ(Reload(pwstr, psize), Result::kSuccess);
  EXPECT_EQ(vault_.GetEntryCount(), 1);
}

/**
 * @brief   Verify old password fails after password change
 */
TEST_F(VaultFileTest, ChangePWOldFails) {
  const char* pwstr = "password";  // original master password
  size_t psize = strlen(pwstr);

  vault_.ChangePW(MakePW("asdf1234"), path_);

  EXPECT_EQ(Reload(pwstr, psize), Result::kFailure);
}

/* ==================================================
 * Error Callback Test
 * ================================================== */

/**
 * @brief   Verify error callback is invoked on failure
 */
TEST_F(VaultFileTest, ErrorCallback) {
  bool cb = false;

  vault_.SetErrorCallback([&](const char* msg) { cb = true; });

  vault_.CloseVault();
  vault_.OpenVault("nonexistent.vault");

  EXPECT_TRUE(cb);
}

/**
 * @brief   Verify getLastError returns error message on failure
 */
TEST_F(VaultFileTest, GetLastError) {
  vault_.CloseVault();

  vault_.OpenVault("nonexistent.vault");

  EXPECT_FALSE(vault_.GetLastError().empty());
}