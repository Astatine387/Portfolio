/**
 * @file    vault_file_test.cpp
 * @brief   Unit tests for Vault file management functions
 * @author  Astatine387
 */

#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "core/secure_key.h"
#include "core/vault.h"
#include "utils/platform.h"

/**
 * @class   VaultFileTest
 * @brief   Test fixture for Vault file operations
 */
class VaultFileTest : public ::testing::Test {
 protected:
  Vault vault_;
  std::string path_ = "test.vault";

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

  /**
   * @brief   Set up test fixture with a master password and an empty vault file
   */
  void SetUp() override { vault_.NewVault(path_, MakePW("password")); }

  /**
   * @brief   Clean up temporary vault files after each test
   */
  void TearDown() override { RemoveFile(path_); }

  /**
   * @brief   Close vault and reopen with the default master password
   * @return  kSuccess on success, kFailure on failure
   */
  Result Reload() { return Reload("password"); }

  /**
   * @brief   Close vault and reopen with a specified password
   * @param   pw_str  Password string
   * @return  kSuccess on success, kFailure on failure
   */
  Result Reload(const char* pw_str) {
    vault_.CloseVault();

    return vault_.OpenVault(path_, MakePW(pw_str));
  }

  /**
   * @brief   Derive a session-compatible key for crafting vault files
   * @param   salt    Salt to derive with
   * @param   params  Argon2id parameters to derive with
   * @return  Derived key
   */
  static SecureKey KeyForFile(const std::array<uint8_t, kSaltSize>& salt, const KdfParams& params = {}) {
    auto key = DeriveKey(std::span<const char>("password", 8), salt, params);

    return std::move(key.value());  // NOLINT(bugprone-unchecked-optional-access)
  }

  /**
   * @brief   Cheapest parameter a vault header can legally carry
   * @return  Argon2id parameter of minimal value
   */
  static KdfParams MinParams() {
    return KdfParams{ .time_cost = kMinTimeCost, .mem_cost = kMinMemCost, .parallelism = kMinParallelism };
  }

  /**
   * @brief   Read an entire file into a byte vector
   * @param   path    File path
   * @return  File contents (empty on failure)
   */
  static std::vector<uint8_t> ReadFile(const std::string& path) {
    FILE* file = nullptr;
    std::vector<uint8_t> buff;

    OpenFile(&file, path, "rb");

    if (file) {
      int64_t size = GetFileSize(file);

      if (size > 0) {
        buff.resize(static_cast<size_t>(size));

        EXPECT_EQ(fread(buff.data(), sizeof(uint8_t), buff.size(), file), buff.size());
      }

      fclose(file);
    }

    return buff;
  }

  /**
   * @brief   Overwrite a file with the given bytes
   * @param   path    File path
   * @param   buff    Bytes to write
   */
  static void WriteFile(const std::string& path, const std::vector<uint8_t>& buff) {
    FILE* file = nullptr;

    OpenFile(&file, path, "wb");

    if (file) {
      EXPECT_EQ(fwrite(buff.data(), sizeof(uint8_t), buff.size(), file), buff.size());

      fclose(file);
    }
  }

  /**
   * @brief   Write a vault file from a header parameter block and an encrypted body
   * @param   path    File path
   * @param   enc     Encrypted body (salt, IV, ciphertext and tag)
   * @param   params  Argon2id parameters to record in the header
   */
  static void WriteVault(const std::string& path, const std::vector<uint8_t>& enc, const KdfParams& params = {}) {
    std::vector<uint8_t> buff(kKdfParamSize + enc.size());

    memcpy(buff.data(), &kMagicNum, kMagicSize);
    memcpy(buff.data() + kMagicSize, &params.time_cost, sizeof(uint32_t));
    memcpy(buff.data() + kMagicSize + sizeof(uint32_t), &params.mem_cost, sizeof(uint32_t));
    memcpy(buff.data() + kMagicSize + 2 * sizeof(uint32_t), &params.parallelism, sizeof(uint32_t));
    memcpy(buff.data() + kKdfParamSize, enc.data(), enc.size());

    WriteFile(path, buff);
  }

  /**
   * @brief   Read the Argon2id parameters out of a vault file header
   * @param   buff    Vault file contents
   * @return  Parameters as stored in the header
   */
  static KdfParams ReadHeaderParams(const std::vector<uint8_t>& buff) {
    KdfParams params{};

    EXPECT_GE(buff.size(), kKdfParamSize);

    memcpy(&params.time_cost, buff.data() + kMagicSize, sizeof(uint32_t));
    memcpy(&params.mem_cost, buff.data() + kMagicSize + sizeof(uint32_t), sizeof(uint32_t));
    memcpy(&params.parallelism, buff.data() + kMagicSize + 2 * sizeof(uint32_t), sizeof(uint32_t));

    return params;
  }

  /**
   * @brief   Replace the Argon2id parameters in the vault file, leaving the body untouched
   * @param   params  Parameters to store
   */
  void PatchHeaderParams(const KdfParams& params) {
    std::vector<uint8_t> buff = ReadFile(path_);

    ASSERT_GE(buff.size(), kKdfParamSize);

    memcpy(buff.data() + kMagicSize, &params.time_cost, sizeof(uint32_t));
    memcpy(buff.data() + kMagicSize + sizeof(uint32_t), &params.mem_cost, sizeof(uint32_t));
    memcpy(buff.data() + kMagicSize + 2 * sizeof(uint32_t), &params.parallelism, sizeof(uint32_t));

    WriteFile(path_, buff);
  }

  /**
   * @brief   Replace the vault file with an empty vault built under the given parameters
   * @param   params  Argon2id parameters to derive with and record
   */
  void MakeVaultWith(const KdfParams& params) {
    uint32_t entry_cnt = 0;
    std::vector<uint8_t> src(kCountSize);

    memcpy(src.data(), &entry_cnt, kCountSize);

    std::array<uint8_t, kSaltSize> salt{};
    salt.fill(0x33);

    SecureKey key = KeyForFile(salt, params);
    std::vector<uint8_t> enc(kSaltSize + kIVSize + src.size() + kTagSize);

    AesGcm aes;

    ASSERT_EQ(aes.Encrypt(src.data(), enc.data(), src.size(), key, salt), Result::kSuccess);

    WriteVault(path_, enc, params);
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
  EXPECT_EQ(Reload("asdf1234"), Result::kFailure);
}

/**
 * @brief   Verify opening non-existent vault fails
 */
TEST_F(VaultFileTest, OpenNonExistent) {
  vault_.CloseVault();

  EXPECT_EQ(vault_.OpenVault("nonexistent.vault", MakePW("asdf1234")), Result::kFailure);
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
  EXPECT_NE(vault_.GetLastError().find("Not a vault file"), std::string::npos);
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
 * @brief   Verify opening a vault where entry count grossly exceeds available data fails
 */
TEST_F(VaultFileTest, OpenInflatedEntryCount) {
  /* Entry count is 10, but there are no actual entries */

  uint32_t entry_cnt = 10;
  size_t src_size = sizeof(uint32_t);

  std::vector<uint8_t> src(src_size);
  memcpy(src.data(), &entry_cnt, sizeof(uint32_t));

  /* Encrypt with a key the vault will re-derive from "password" */

  std::array<uint8_t, kSaltSize> salt{};
  salt.fill(0x11);
  SecureKey key = KeyForFile(salt);

  size_t enc_size = kSaltSize + kIVSize + src_size + kTagSize;
  std::vector<uint8_t> enc(enc_size);

  AesGcm aes;
  aes.Encrypt(src.data(), enc.data(), src_size, key, salt);

  /* Write vault file */

  WriteVault(path_, enc);

  EXPECT_EQ(Reload(), Result::kFailure);
}

/**
 * @brief   Verify opening a vault where entry count exceeds actual entries fails
 */
TEST_F(VaultFileTest, OpenPartialEntryData) {
  /* Entry count is 2, but only 1 entry is valid */

  Entry entry;
  entry.site = "Google";
  entry.acc = "user@google.com";

  const char* epw = "password";
  entry.pw_len = static_cast<uint32_t>(strlen(epw));

  uint32_t entry_cnt = 2;
  size_t entry_size = entry.Size();
  size_t src_size = sizeof(uint32_t) + entry_size + kMinEntrySize;

  std::vector<uint8_t> src(src_size, 0xFF);

  size_t cur = 0;

  memcpy(src.data() + cur, &entry_cnt, sizeof(uint32_t));
  cur += sizeof(uint32_t);

  std::span<const uint8_t> epw_span(reinterpret_cast<const uint8_t*>(epw), entry.pw_len);

  entry.Serialize(std::span(src).subspan(cur), epw_span);

  /* Encrypt with a key the vault will re-derive from "password" */

  std::array<uint8_t, kSaltSize> salt{};
  salt.fill(0x22);
  SecureKey key = KeyForFile(salt);

  size_t enc_size = kSaltSize + kIVSize + src_size + kTagSize;
  std::vector<uint8_t> enc(enc_size);

  AesGcm aes;
  aes.Encrypt(src.data(), enc.data(), src_size, key, salt);

  /* Write vault file */

  WriteVault(path_, enc);

  EXPECT_EQ(Reload(), Result::kFailure);
}

/**
 * @brief   Verify decryption fails when the ciphertext is tampered
 */
TEST_F(VaultFileTest, OpenTamperedCiphertext) {
  FILE* file = nullptr;

  /* Read back the valid vault file created in SetUp */

  OpenFile(&file, path_, "rb");

  ASSERT_NE(file, nullptr);

  const int64_t tmp = GetFileSize(file);

  ASSERT_GT(tmp, 0);

  const size_t fsize = static_cast<size_t>(tmp);

  std::vector<uint8_t> buff(fsize);

  ASSERT_EQ(fread(buff.data(), sizeof(uint8_t), fsize, file), fsize);

  fclose(file);

  /* Flip the first ciphertext byte, leaving the header, salt and IV intact */

  const size_t offset = kKdfParamSize + kSaltSize + kIVSize;

  ASSERT_LT(offset, fsize);

  buff[offset] ^= 0xFF;

  EXPECT_EQ(memcmp(buff.data(), &kMagicNum, kMagicSize), 0);

  /* Write the tampered vault back */

  OpenFile(&file, path_, "wb");

  ASSERT_NE(file, nullptr);
  ASSERT_EQ(fwrite(buff.data(), sizeof(uint8_t), fsize, file), fsize);

  fclose(file);

  EXPECT_EQ(Reload(), Result::kFailure);
}

/* ==================================================
 * Header Parameter Test
 * ================================================== */

/**
 * @brief   Verify a new vault records the current default Argon2id parameters
 */
TEST_F(VaultFileTest, HeaderRecordsKdfParams) {
  const std::vector<uint8_t> buff = ReadFile(path_);

  ASSERT_EQ(buff.size(), static_cast<size_t>(kMinSize));

  const KdfParams params = ReadHeaderParams(buff);

  EXPECT_EQ(params.time_cost, kTimeCost);
  EXPECT_EQ(params.mem_cost, kMemCost);
  EXPECT_EQ(params.parallelism, kParallelism);
}

/**
 * @brief   Verify the key is derived with the header parameters rather than the build defaults
 */
TEST_F(VaultFileTest, OpenUsesHeaderKdfParams) {
  MakeVaultWith(MinParams());

  EXPECT_EQ(Reload(), Result::kSuccess);
  EXPECT_EQ(vault_.GetEntryCount(), 0);
}

/**
 * @brief   Verify parameters outside the accepted range are rejected before any key derivation
 */
TEST_F(VaultFileTest, OpenRejectsOutOfRangeKdfParams) {
  const std::array<KdfParams, 6> cases{
    KdfParams{ .time_cost = kMinTimeCost - 1, .mem_cost = kMemCost, .parallelism = kParallelism },
    KdfParams{ .time_cost = kMaxTimeCost + 1, .mem_cost = kMemCost, .parallelism = kParallelism },
    KdfParams{ .time_cost = kTimeCost, .mem_cost = kMinMemCost - 1, .parallelism = kParallelism },
    KdfParams{ .time_cost = kTimeCost, .mem_cost = kMaxMemCost + 1, .parallelism = kParallelism },
    KdfParams{ .time_cost = kTimeCost, .mem_cost = kMemCost, .parallelism = kMinParallelism - 1 },
    KdfParams{ .time_cost = kTimeCost, .mem_cost = kMemCost, .parallelism = kMaxParallelism + 1 },
  };

  for (const KdfParams& params : cases) {
    SCOPED_TRACE(testing::Message() << "t=" << params.time_cost << " m=" << params.mem_cost
                                    << " p=" << params.parallelism);

    PatchHeaderParams(params);

    EXPECT_EQ(Reload(), Result::kFailure);
    EXPECT_NE(vault_.GetLastError().find("Unsupported key derivation parameters"), std::string::npos);
  }
}

/**
 * @brief   Verify a file written before the parameter block existed is rejected as malformed
 */
TEST_F(VaultFileTest, OpenLegacyFormatFails) {
  vault_.CreateEntry("Google", "user@google.com", MakePW("password"));

  ASSERT_EQ(vault_.SaveVault(path_), Result::kSuccess);

  /* Rebuild the file without the parameter block, the way older builds wrote it */

  std::vector<uint8_t> buff = ReadFile(path_);

  buff.erase(buff.begin() + kMagicSize, buff.begin() + static_cast<std::ptrdiff_t>(kKdfParamSize));

  ASSERT_GE(buff.size(), static_cast<size_t>(kMinSize));

  WriteFile(path_, buff);

  /* The leading salt bytes now sit where the parameters belong and fall outside the accepted range */

  EXPECT_EQ(Reload(), Result::kFailure);
  EXPECT_NE(vault_.GetLastError().find("Unsupported key derivation parameters"), std::string::npos);
}

/**
 * @brief   Verify a save keeps the parameters the open vault was derived with
 */
TEST_F(VaultFileTest, SavePreservesKdfParams) {
  MakeVaultWith(MinParams());

  ASSERT_EQ(Reload(), Result::kSuccess);
  ASSERT_EQ(vault_.SaveVault(path_), Result::kSuccess);

  const KdfParams params = ReadHeaderParams(ReadFile(path_));

  EXPECT_EQ(params.time_cost, kMinTimeCost);
  EXPECT_EQ(params.mem_cost, kMinMemCost);
  EXPECT_EQ(params.parallelism, kMinParallelism);
}

/**
 * @brief   Verify a password change lifts the vault to the current default parameters
 */
TEST_F(VaultFileTest, ChangePWUpdatesKdfParams) {
  MakeVaultWith(MinParams());

  ASSERT_EQ(Reload(), Result::kSuccess);
  ASSERT_EQ(vault_.ChangePW(MakePW("asdf1234"), path_), Result::kSuccess);

  const KdfParams params = ReadHeaderParams(ReadFile(path_));

  EXPECT_EQ(params.time_cost, kTimeCost);
  EXPECT_EQ(params.mem_cost, kMemCost);
  EXPECT_EQ(params.parallelism, kParallelism);
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

  EXPECT_NE(entries.find({ .site = "Google", .acc = "user1@google.com" }), entries.end());
  EXPECT_NE(entries.find({ .site = "Microsoft", .acc = "user2@microsoft.com" }), entries.end());
}

/**
 * @brief   Verify passwords are correctly preserved through save and reload
 */
TEST_F(VaultFileTest, SavePreservesPasswords) {
  Password pw = MakePW("password");

  vault_.CreateEntry("Google", "user@google.com", pw);
  vault_.SaveVault(path_);

  EXPECT_EQ(Reload(), Result::kSuccess);

  Password got;

  EXPECT_TRUE(vault_.GetEntryPW("Google", "user@google.com", got));
  EXPECT_TRUE(got.Equal(pw));
}

/**
 * @brief   Verify saving an empty vault and reopening it succeeds
 */
TEST_F(VaultFileTest, SaveEmptyVault) {
  vault_.SaveVault(path_);

  EXPECT_EQ(Reload(), Result::kSuccess);
  EXPECT_EQ(vault_.GetEntryCount(), 0);
}

/**
 * @brief   Verify each save reuses the session salt but writes a fresh IV
 */
TEST_F(VaultFileTest, SaveWritesFreshIV) {
  vault_.CreateEntry("Google", "user@google.com", MakePW("password"));

  ASSERT_EQ(vault_.SaveVault(path_), Result::kSuccess);
  std::vector<uint8_t> first = ReadFile(path_);

  ASSERT_EQ(vault_.SaveVault(path_), Result::kSuccess);
  std::vector<uint8_t> second = ReadFile(path_);

  ASSERT_EQ(first.size(), second.size());
  ASSERT_GT(first.size(), kKdfParamSize + kSaltSize + kIVSize + kTagSize);

  const size_t salt_off = kKdfParamSize;
  const size_t iv_off = kKdfParamSize + kSaltSize;
  const size_t ct_off = kKdfParamSize + kSaltSize + kIVSize;

  /* Salt is reused so the key stays stable */

  EXPECT_EQ(memcmp(first.data() + salt_off, second.data() + salt_off, kSaltSize), 0);

  /* IV is regenerated on every write */

  EXPECT_NE(memcmp(first.data() + iv_off, second.data() + iv_off, kIVSize), 0);

  /* Ciphertext and tag differ under the fresh IV */

  EXPECT_NE(memcmp(first.data() + ct_off, second.data() + ct_off, first.size() - ct_off), 0);

  /* The vault still opens correctly after the repeated saves */

  EXPECT_EQ(Reload(), Result::kSuccess);
  EXPECT_EQ(vault_.GetEntryCount(), 1);
}

/**
 * @brief   Verify SaveVault fails when no vault is open
 */
TEST_F(VaultFileTest, SaveWithoutOpenVault) {
  vault_.CloseVault();

  EXPECT_EQ(vault_.SaveVault(path_), Result::kFailure);
  EXPECT_NE(vault_.GetLastError().find("No vault is open"), std::string::npos);
}

/**
 * @brief   Verify ChangePW fails when no vault is open
 */
TEST_F(VaultFileTest, ChangePWWithoutOpenVault) {
  vault_.CloseVault();

  EXPECT_EQ(vault_.ChangePW(MakePW("asdf1234"), path_), Result::kFailure);
  EXPECT_NE(vault_.GetLastError().find("No vault is open"), std::string::npos);
}

/* ==================================================
 * Password Verification Test
 * ================================================== */

/**
 * @brief   Verify the correct master password matches the session key
 */
TEST_F(VaultFileTest, VerifyPWCorrect) {
  EXPECT_TRUE(vault_.VerifyPW(MakePW("password")));
}

/**
 * @brief   Verify a wrong master password does not match the session key
 */
TEST_F(VaultFileTest, VerifyPWWrong) {
  EXPECT_FALSE(vault_.VerifyPW(MakePW("asdf1234")));
}

/* ==================================================
 * Change Password Test
 * ================================================== */

/**
 * @brief   Verify changing master password and reopening with new password succeeds
 */
TEST_F(VaultFileTest, ChangePW) {
  vault_.CreateEntry("Google", "user@google.com", MakePW("password"));

  EXPECT_EQ(vault_.ChangePW(MakePW("asdf1234"), path_), Result::kSuccess);
  EXPECT_EQ(Reload("asdf1234"), Result::kSuccess);
  EXPECT_EQ(vault_.GetEntryCount(), 1);
}

/**
 * @brief   Verify old password fails after password change
 */
TEST_F(VaultFileTest, ChangePWOldFails) {
  vault_.ChangePW(MakePW("asdf1234"), path_);

  EXPECT_EQ(Reload("password"), Result::kFailure);
}

/**
 * @brief   Verify the session key is updated after a password change
 */
TEST_F(VaultFileTest, ChangePWUpdatesSession) {
  vault_.ChangePW(MakePW("asdf1234"), path_);

  EXPECT_TRUE(vault_.VerifyPW(MakePW("asdf1234")));
  EXPECT_FALSE(vault_.VerifyPW(MakePW("password")));
}

/**
 * @brief   Verify a failed save leaves the session key and salt untouched
 */
TEST_F(VaultFileTest, ChangePWSaveFailurePreservesSession) {
  EXPECT_EQ(vault_.ChangePW(MakePW("asdf1234"), "no_such_dir/child.vault"), Result::kFailure);

  EXPECT_TRUE(vault_.VerifyPW(MakePW("password")));
  EXPECT_FALSE(vault_.VerifyPW(MakePW("asdf1234")));
}

/* ==================================================
 * Error Callback Test
 * ================================================== */

/**
 * @brief   Verify error callback is invoked on failure
 */
TEST_F(VaultFileTest, ErrorCallback) {
  bool cb = false;

  vault_.SetErrorCallback([&](const char*) { cb = true; });

  vault_.CloseVault();
  vault_.OpenVault("nonexistent.vault", MakePW("password"));

  EXPECT_TRUE(cb);
}

/**
 * @brief   Verify getLastError returns error message on failure
 */
TEST_F(VaultFileTest, GetLastError) {
  vault_.CloseVault();

  vault_.OpenVault("nonexistent.vault", MakePW("password"));

  EXPECT_FALSE(vault_.GetLastError().empty());
}
