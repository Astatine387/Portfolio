/**
 * @file    aes_gcm_test.cpp
 * @brief   Unit tests for AES-GCM class
 * @author  Astatine387
 */

#include "core/aes_gcm.h"

#include <gtest/gtest.h>
#include <openssl/err.h>

#include <array>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "core/secure_key.h"
#include "utils/platform.h"

/**
 * @class   AesGcmTest
 * @brief   Test fixture for AesGcm encryption/decryption tests
 */
class AesGcmTest : public ::testing::Test {
 protected:
  std::string src_path_ = "test_src.tmp";
  std::string enc_path_ = "test_enc.tmp";
  std::string dec_path_ = "test_dec.tmp";

  /**
   * @brief   Clean up temporary files after each test
   */
  void TearDown() override {
    RemoveFile(src_path_);
    RemoveFile(enc_path_);
    RemoveFile(dec_path_);
  }

  /**
   * @brief   Small Argon2id parameters to keep key derivation fast
   */
  static KdfParams FastParams() { return KdfParams{ .time_cost = 1, .mem_cost = 8, .parallelism = 1 }; }

  /**
   * @brief   Build a fixed salt
   */
  static std::array<uint8_t, kSaltSize> MakeSalt(uint8_t fill) {
    std::array<uint8_t, kSaltSize> salt{};
    salt.fill(fill);
    return salt;
  }

  /**
   * @brief   Derive a key from a password and salt
   */
  static SecureKey MakeKey(const char* pw, const std::array<uint8_t, kSaltSize>& salt) {
    auto key = DeriveKey(std::span<const char>(pw, std::strlen(pw)), salt, FastParams());
    return std::move(key.value());  // NOLINT(bugprone-unchecked-optional-access)
  }

  /**
   * @brief   Create test file
   * @param   path    File path
   * @param   data    File content
   * @param   size    File size
   */
  void Create(const std::string& path, std::vector<uint8_t>& data, int size) {
    FILE* file = nullptr;

    OpenFile(&file, path, "wb");

    if (file) {
      if (size > 0) {
        fwrite(data.data(), sizeof(uint8_t), size, file);
      }

      fclose(file);
    }
  }

  /**
   * @brief   Read file into buffer
   * @param   path    Source file path
   * @param   vec     Destination buffer
   */
  void Read(std::string& path, std::vector<uint8_t>& vec) {
    FILE* file = nullptr;
    uint64_t size;

    OpenFile(&file, path, "rb");

    if (!file)
      return;

    size = GetFileSize(file);

    vec.resize(size);

    fread(vec.data(), sizeof(uint8_t), size, file);

    fclose(file);
  }
};

/* ==================================================
 * Encryption/Decryption Tests
 * ================================================== */

/**
 * @brief   Verify encryption and decryption round-trip preserves data
 */
TEST_F(AesGcmTest, EncryptDecryptBasic) {
  AesGcm aes;
  FILE *src = nullptr, *dst = nullptr;
  const char* data = "Hello, world!";
  int dsize = static_cast<int>(strlen(data));
  Result res;
  std::vector<uint8_t> orig(data, data + dsize), copy;

  auto salt = MakeSalt(0xA5);
  SecureKey key = MakeKey("password", salt);

  Create(src_path_, orig, dsize);

  /* Encrypt */

  OpenFile(&src, src_path_, "rb");
  OpenFile(&dst, enc_path_, "wb+");

  res = aes.Encrypt(src, dst, key, salt);

  if (src) {
    fclose(src);
  }

  if (dst) {
    fclose(dst);
  }

  EXPECT_EQ(res, Result::kSuccess);

  /* Decrypt */

  OpenFile(&src, enc_path_, "rb");
  OpenFile(&dst, dec_path_, "wb+");

  res = aes.Decrypt(src, dst, key);

  if (src) {
    fclose(src);
  }

  if (dst) {
    fclose(dst);
  }

  EXPECT_EQ(res, Result::kSuccess);

  /* Compare with original */

  Read(dec_path_, copy);

  EXPECT_EQ(orig, copy);
}

/**
 * @brief   Verify encryption produces different ciphertext each time (fresh IV)
 */
TEST_F(AesGcmTest, EncryptProducesDifferentOutput) {
  AesGcm aes;
  FILE *src = nullptr, *dst = nullptr;
  const char* data = "Hello, world!";
  int dsize = static_cast<int>(strlen(data));
  std::vector<uint8_t> orig(data, data + dsize), enc0, enc1;

  auto salt = MakeSalt(0xA5);
  SecureKey key = MakeKey("password", salt);

  Create(src_path_, orig, dsize);

  /* First encryption */

  OpenFile(&src, src_path_, "rb");
  OpenFile(&dst, enc_path_, "wb+");

  aes.Encrypt(src, dst, key, salt);

  if (src) {
    fclose(src);
  }

  if (dst) {
    fclose(dst);
  }

  /* Second encryption of the same source with the same key and salt */

  OpenFile(&src, src_path_, "rb");
  OpenFile(&dst, dec_path_, "wb+");

  aes.Encrypt(src, dst, key, salt);

  if (src) {
    fclose(src);
  }

  if (dst) {
    fclose(dst);
  }

  /* Ciphertexts must differ because a fresh IV is generated each time */

  Read(enc_path_, enc0);
  Read(dec_path_, enc1);

  EXPECT_NE(enc0, enc1);
}

/**
 * @brief   Verify a reused AesGcm frees its previous context before re-init
 */
TEST_F(AesGcmTest, ReuseFreesPreviousContext) {
  AesGcm aes;
  FILE *src = nullptr, *dst = nullptr;
  const char* data = "Hello, world!";
  int dsize = static_cast<int>(strlen(data));
  std::vector<uint8_t> orig(data, data + dsize);
  Result res0, res1;

  auto salt = MakeSalt(0xA5);
  SecureKey key = MakeKey("password", salt);

  Create(src_path_, orig, dsize);

  /* First encryption - leaves a live context on the object */

  OpenFile(&src, src_path_, "rb");
  OpenFile(&dst, enc_path_, "wb+");

  res0 = aes.Encrypt(src, dst, key, salt);

  if (src) {
    fclose(src);
  }

  if (dst) {
    fclose(dst);
  }

  /* Second encryption - EncryptInit must free the previous context */

  OpenFile(&src, src_path_, "rb");
  OpenFile(&dst, dec_path_, "wb+");

  res1 = aes.Encrypt(src, dst, key, salt);

  if (src) {
    fclose(src);
  }

  if (dst) {
    fclose(dst);
  }

  EXPECT_EQ(res0, Result::kSuccess);
  EXPECT_EQ(res1, Result::kSuccess);
}

/* ==================================================
 * Authentication Tests
 * ================================================== */

/**
 * @brief   Verify decryption with the wrong key fails
 */
TEST_F(AesGcmTest, DecryptWrongKey) {
  AesGcm aes;
  FILE *src = nullptr, *dst = nullptr;
  const char* data = "Hello, world!";
  int dsize = static_cast<int>(strlen(data));
  Result res;
  std::vector<uint8_t> orig(data, data + dsize);

  auto salt = MakeSalt(0xA5);
  SecureKey key0 = MakeKey("password", salt);
  SecureKey key1 = MakeKey("asdf1234", salt);

  Create(src_path_, orig, dsize);

  /* Encrypt */

  OpenFile(&src, src_path_, "rb");
  OpenFile(&dst, enc_path_, "wb+");

  aes.Encrypt(src, dst, key0, salt);

  if (src) {
    fclose(src);
  }

  if (dst) {
    fclose(dst);
  }

  /* Decrypt with the wrong key */

  OpenFile(&src, enc_path_, "rb");
  OpenFile(&dst, dec_path_, "wb");

  res = aes.Decrypt(src, dst, key1);

  if (src) {
    fclose(src);
  }

  if (dst) {
    fclose(dst);
  }

  EXPECT_EQ(res, Result::kFailure);
}

/**
 * @brief   Verify tampering with ciphertext causes decryption failure
 */
TEST_F(AesGcmTest, TamperedCiphertext) {
  AesGcm aes;
  FILE *src = nullptr, *dst = nullptr;
  const char* data = "Hello, world!";
  int dsize = static_cast<int>(strlen(data));
  Result res;
  std::vector<uint8_t> orig(data, data + dsize), copy;

  auto salt = MakeSalt(0xA5);
  SecureKey key = MakeKey("password", salt);

  Create(src_path_, orig, dsize);

  /* Encrypt */

  OpenFile(&src, src_path_, "rb");
  OpenFile(&dst, enc_path_, "wb+");

  aes.Encrypt(src, dst, key, salt);

  if (src) {
    fclose(src);
  }

  if (dst) {
    fclose(dst);
  }

  /* Tamper ciphertext */

  Read(enc_path_, copy);

  copy[kSaltSize + kIVSize] ^= 0xFF;

  Create(enc_path_, copy, static_cast<int>(copy.size()));

  /* Decrypt */

  OpenFile(&src, enc_path_, "rb");
  OpenFile(&dst, dec_path_, "wb+");

  res = aes.Decrypt(src, dst, key);

  if (src) {
    fclose(src);
  }

  if (dst) {
    fclose(dst);
  }

  EXPECT_EQ(res, Result::kFailure);
}

/**
 * @brief   Verify tampering with the authentication tag causes decryption failure
 */
TEST_F(AesGcmTest, TamperedTag) {
  AesGcm aes;
  FILE *src = nullptr, *dst = nullptr;
  const char* data = "Hello, world!";
  int dsize = static_cast<int>(strlen(data));
  Result res;
  std::vector<uint8_t> orig(data, data + dsize), copy;

  auto salt = MakeSalt(0xA5);
  SecureKey key = MakeKey("password", salt);

  Create(src_path_, orig, dsize);

  /* Encrypt */

  OpenFile(&src, src_path_, "rb");
  OpenFile(&dst, enc_path_, "wb+");

  aes.Encrypt(src, dst, key, salt);

  if (src) {
    fclose(src);
  }

  if (dst) {
    fclose(dst);
  }

  /* Tamper authentication tag (last byte of the file) */

  Read(enc_path_, copy);

  copy[copy.size() - 1] ^= 0xFF;

  Create(enc_path_, copy, static_cast<int>(copy.size()));

  /* Decrypt */

  OpenFile(&src, enc_path_, "rb");
  OpenFile(&dst, dec_path_, "wb+");

  res = aes.Decrypt(src, dst, key);

  if (src) {
    fclose(src);
  }

  if (dst) {
    fclose(dst);
  }

  EXPECT_EQ(res, Result::kFailure);
}

/* ==================================================
 * Edge Case Tests
 * ================================================== */

/**
 * @brief   Verify empty file can be encrypted and decrypted
 */
TEST_F(AesGcmTest, EmptyFile) {
  AesGcm aes;
  FILE *src = nullptr, *dst = nullptr;
  std::vector<uint8_t> orig, copy;
  int dsize = 0;
  Result res;

  auto salt = MakeSalt(0xA5);
  SecureKey key = MakeKey("password", salt);

  Create(src_path_, orig, dsize);

  /* Encrypt */

  OpenFile(&src, src_path_, "rb");
  OpenFile(&dst, enc_path_, "wb+");

  res = aes.Encrypt(src, dst, key, salt);

  if (src) {
    fclose(src);
  }

  if (dst) {
    fclose(dst);
  }

  EXPECT_EQ(res, Result::kSuccess);

  /* Decrypt */

  OpenFile(&src, enc_path_, "rb");
  OpenFile(&dst, dec_path_, "wb+");

  res = aes.Decrypt(src, dst, key);

  if (src) {
    fclose(src);
  }

  if (dst) {
    fclose(dst);
  }

  EXPECT_EQ(res, Result::kSuccess);

  /* Compare with original */

  Read(dec_path_, copy);

  EXPECT_EQ(orig, copy);
}

/**
 * @brief   Verify file with exact buffer size works correctly
 */
TEST_F(AesGcmTest, ExactBuffSizeFile) {
  AesGcm aes;
  FILE *src = nullptr, *dst = nullptr;
  std::vector<uint8_t> orig, copy;
  int dsize = kBlockSize * kBuffSize;
  Result res;

  auto salt = MakeSalt(0xA5);
  SecureKey key = MakeKey("password", salt);

  orig.resize(dsize, 'a');

  Create(src_path_, orig, dsize);

  /* Encrypt */

  OpenFile(&src, src_path_, "rb");
  OpenFile(&dst, enc_path_, "wb+");

  res = aes.Encrypt(src, dst, key, salt);

  if (src) {
    fclose(src);
  }

  if (dst) {
    fclose(dst);
  }

  EXPECT_EQ(res, Result::kSuccess);

  /* Decrypt */

  OpenFile(&src, enc_path_, "rb");
  OpenFile(&dst, dec_path_, "wb+");

  res = aes.Decrypt(src, dst, key);

  if (src) {
    fclose(src);
  }

  if (dst) {
    fclose(dst);
  }

  EXPECT_EQ(res, Result::kSuccess);

  /* Compare with original */

  Read(dec_path_, copy);

  EXPECT_EQ(orig, copy);
}

/**
 * @brief   Verify arbitrary sized file works correctly
 */
TEST_F(AesGcmTest, ArbitrarySizeFile) {
  AesGcm aes;
  FILE *src = nullptr, *dst = nullptr;
  std::vector<uint8_t> orig, copy;
  int dsize = 50000;
  Result res;

  auto salt = MakeSalt(0xA5);
  SecureKey key = MakeKey("password", salt);

  orig.resize(dsize, 'a');

  Create(src_path_, orig, dsize);

  /* Encrypt */

  OpenFile(&src, src_path_, "rb");
  OpenFile(&dst, enc_path_, "wb+");

  res = aes.Encrypt(src, dst, key, salt);

  if (src) {
    fclose(src);
  }

  if (dst) {
    fclose(dst);
  }

  EXPECT_EQ(res, Result::kSuccess);

  /* Decrypt */

  OpenFile(&src, enc_path_, "rb");
  OpenFile(&dst, dec_path_, "wb+");

  res = aes.Decrypt(src, dst, key);

  if (src) {
    fclose(src);
  }

  if (dst) {
    fclose(dst);
  }

  EXPECT_EQ(res, Result::kSuccess);

  /* Compare with original */

  Read(dec_path_, copy);

  EXPECT_EQ(orig, copy);
}

/* ==================================================
 * Callback Tests
 * ================================================== */

/**
 * @brief   Verify progress callback is invoked during encryption
 */
TEST_F(AesGcmTest, ProgressCallback) {
  AesGcm aes;
  FILE *src = nullptr, *dst = nullptr;
  std::vector<uint8_t> orig;
  int dsize = kBlockSize * kBuffSize * 10;
  int cnt = 0, last = -1;

  auto salt = MakeSalt(0xA5);
  SecureKey key = MakeKey("password", salt);

  orig.resize(dsize, 'a');

  Create(src_path_, orig, dsize);

  /* Encrypt with progress callback */

  OpenFile(&src, src_path_, "rb");
  OpenFile(&dst, enc_path_, "wb+");

  aes.SetProgressCallback([&](int perc, bool* cancelled) {
    cnt++;

    EXPECT_GE(perc, last);

    last = perc;
  });

  aes.Encrypt(src, dst, key, salt);

  if (src) {
    fclose(src);
  }

  if (dst) {
    fclose(dst);
  }

  EXPECT_GT(cnt, 0);
}

/**
 * @brief   Verify error callback is invoked on decryption failure
 */
TEST_F(AesGcmTest, ErrorCallback) {
  AesGcm aes;
  FILE *src = nullptr, *dst = nullptr;
  bool b = false;
  const char* data = "Hello, world!";
  int dsize = static_cast<int>(strlen(data));
  std::vector<uint8_t> orig(data, data + dsize);

  auto salt = MakeSalt(0xA5);
  SecureKey key0 = MakeKey("password", salt);
  SecureKey key1 = MakeKey("asdf1234", salt);

  Create(src_path_, orig, dsize);

  /* Encrypt */

  OpenFile(&src, src_path_, "rb");
  OpenFile(&dst, enc_path_, "wb+");

  aes.Encrypt(src, dst, key0, salt);

  if (src) {
    fclose(src);
  }

  if (dst) {
    fclose(dst);
  }

  /* Decrypt with the wrong key and an error callback */

  OpenFile(&src, enc_path_, "rb");
  OpenFile(&dst, dec_path_, "wb+");

  aes.SetErrorCallback([&](const char* msg) { b = true; });

  aes.Decrypt(src, dst, key1);

  if (src) {
    fclose(src);
  }

  if (dst) {
    fclose(dst);
  }

  EXPECT_TRUE(b);
}

/**
 * @brief   Verify ReportError formats and appends queued OpenSSL errors
 */
TEST_F(AesGcmTest, ErrorCallbackFormatsQueue) {
  AesGcm aes;
  FILE *src = nullptr, *dst = nullptr;
  bool called = false;
  std::string captured;
  const char* data = "Hello, world!";
  int dsize = static_cast<int>(strlen(data));
  std::vector<uint8_t> orig(data, data + dsize);

  auto salt = MakeSalt(0xA5);
  SecureKey key0 = MakeKey("password", salt);
  SecureKey key1 = MakeKey("asdf1234", salt);

  Create(src_path_, orig, dsize);

  /* Encrypt with the correct key */

  OpenFile(&src, src_path_, "rb");
  OpenFile(&dst, enc_path_, "wb+");

  aes.Encrypt(src, dst, key0, salt);

  if (src) {
    fclose(src);
  }

  if (dst) {
    fclose(dst);
  }

  /* Seed the OpenSSL error queue, then fail decryption with the wrong key */

  OpenFile(&src, enc_path_, "rb");
  OpenFile(&dst, dec_path_, "wb+");

  aes.SetErrorCallback([&](const char* msg) {
    called = true;
    captured = msg;
  });

  ERR_clear_error();
  ERR_raise(ERR_LIB_USER, ERR_R_INTERNAL_ERROR);

  aes.Decrypt(src, dst, key1);

  if (src) {
    fclose(src);
  }

  if (dst) {
    fclose(dst);
  }

  EXPECT_TRUE(called);
  EXPECT_NE(captured.find(" -> "), std::string::npos);
}

/* ==================================================
 * Cancellation Tests
 * ================================================== */

/**
 * @brief   Verify cancellation works
 */
TEST_F(AesGcmTest, Cancellation) {
  AesGcm aes;
  FILE *src = nullptr, *dst = nullptr;
  std::vector<uint8_t> orig;
  int dsize = kBlockSize * kBuffSize * 10;
  int cnt = 0;
  Result res;

  auto salt = MakeSalt(0xA5);
  SecureKey key = MakeKey("password", salt);

  orig.resize(dsize, 'a');

  Create(src_path_, orig, dsize);

  /* Encrypt and cancel after the second callback */

  OpenFile(&src, src_path_, "rb");
  OpenFile(&dst, enc_path_, "wb+");

  aes.SetProgressCallback([&](int perc, bool* cancelled) {
    cnt++;

    if (cnt >= 2) {
      *cancelled = true;
    }
  });

  res = aes.Encrypt(src, dst, key, salt);

  if (src) {
    fclose(src);
  }

  if (dst) {
    fclose(dst);
  }

  EXPECT_EQ(res, Result::kFailure);
  EXPECT_GE(cnt, 2);
  EXPECT_LE(cnt, 3);
}

/**
 * @brief   Verify cancelling during the decryption write pass waits for the ongoing async write before reporting
 * failure
 */
TEST_F(AesGcmTest, CancelDuringWritePass) {
  AesGcm aes;
  FILE *src = nullptr, *dst = nullptr;
  std::vector<uint8_t> orig;
  int dsize = kBlockSize * kBuffSize * 10;
  Result res;

  auto salt = MakeSalt(0xA5);
  SecureKey key = MakeKey("password", salt);

  orig.resize(dsize, 'a');

  Create(src_path_, orig, dsize);

  /* Encrypt first to produce a valid ciphertext */

  OpenFile(&src, src_path_, "rb");
  OpenFile(&dst, enc_path_, "wb+");

  aes.Encrypt(src, dst, key, salt);

  if (src) {
    fclose(src);
  }

  if (dst) {
    fclose(dst);
  }

  /* Decrypt, cancelling once the write pass is in progress (perc > 50) */

  OpenFile(&src, enc_path_, "rb");
  OpenFile(&dst, dec_path_, "wb+");

  aes.SetProgressCallback([&](int perc, bool* cancelled) {
    if (perc > 50) {
      *cancelled = true;
    }
  });

  res = aes.Decrypt(src, dst, key);

  if (src) {
    fclose(src);
  }

  if (dst) {
    fclose(dst);
  }

  EXPECT_EQ(res, Result::kFailure);
}

/* ==================================================
 * Write Failure Tests
 * ================================================== */

/**
 * @brief   Verify a failed asynchronous write is recorded and reported
 */
TEST_F(AesGcmTest, WriteFailureIsSticky) {
  AesGcm aes;
  FILE *src = nullptr, *dst = nullptr;
  std::vector<uint8_t> orig;
  int dsize = kBlockSize * kBuffSize * 4;
  std::string captured;
  Result res;

  auto salt = MakeSalt(0x00);
  SecureKey key = MakeKey("password", salt);

  orig.resize(dsize, 'a');

  Create(src_path_, orig, dsize);

  /* Encrypt first to produce a valid ciphertext */

  OpenFile(&src, src_path_, "rb");
  OpenFile(&dst, enc_path_, "wb+");

  aes.Encrypt(src, dst, key, salt);

  if (src) {
    fclose(src);
  }

  if (dst) {
    fclose(dst);
  }

  /* Decrypt into a read-only destination so every asynchronous write fails */

  Create(dec_path_, orig, 1);

  OpenFile(&src, enc_path_, "rb");
  OpenFile(&dst, dec_path_, "rb");

  aes.SetErrorCallback([&](const char* msg) { captured += msg; });

  res = aes.Decrypt(src, dst, key);

  if (src) {
    fclose(src);
  }

  if (dst) {
    fclose(dst);
  }

  EXPECT_EQ(res, Result::kFailure);
  EXPECT_NE(captured.find("Write failed"), std::string::npos);
}

/**
 * @brief   Verify a thrown error callback doesn't escape the noexcept writer thread
 */
TEST_F(AesGcmTest, ThrowingErrorCallbackDoesNotTerminate) {
  AesGcm aes;
  FILE *src = nullptr, *dst = nullptr;
  std::vector<uint8_t> orig;
  int dsize = kBlockSize * kBuffSize * 4;
  int calls = 0;
  Result res = Result::kSuccess;

  auto salt = MakeSalt(0x00);
  SecureKey key = MakeKey("password", salt);

  orig.resize(dsize, 'a');

  Create(src_path_, orig, dsize);

  /* Encrypt first to produce a valid ciphertext */

  OpenFile(&src, src_path_, "rb");
  OpenFile(&dst, enc_path_, "wb+");

  aes.Encrypt(src, dst, key, salt);

  if (src) {
    fclose(src);
  }

  if (dst) {
    fclose(dst);
  }

  /* A write failure drives ReportError, and the callback throws out of the writer thread */

  Create(dec_path_, orig, 1);

  OpenFile(&src, enc_path_, "rb");
  OpenFile(&dst, dec_path_, "rb");

  aes.SetErrorCallback([&](const char* msg) {
    calls++;

    throw std::runtime_error("error callback failed");
  });

  EXPECT_NO_THROW(res = aes.Decrypt(src, dst, key));

  if (src) {
    fclose(src);
  }

  if (dst) {
    fclose(dst);
  }

  EXPECT_EQ(res, Result::kFailure);
  EXPECT_GT(calls, 0);
}