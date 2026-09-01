/**
 * @file    aes_gcm_test.cpp
 * @brief   Unit tests for AES-GCM class
 * @author  Astatine387
 */

#include "core/aes_gcm.h"

#include <gtest/gtest.h>
#include <openssl/err.h>

#include <array>
#include <atomic>
#include <cstring>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "core/file_header.h"
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
   * @brief   The cheapest Argon2id parameters this build accepts
   */
  static KdfParams MinParams() {
    return KdfParams{ .time_cost = kMinTimeCost, .mem_cost = kMinMemCost, .parallelism = kMinParallelism };
  }

  /**
   * @brief   Build a fixed salt
   */
  static std::array<uint8_t, kSaltSize> MakeSalt(uint8_t fill) {
    std::array<uint8_t, kSaltSize> salt{};
    salt.fill(fill);
    return salt;
  }

  /**
   * @brief   Convert a C string to a byte vector
   */
  static std::vector<uint8_t> ToBytes(const char* str) {
    const auto* bytes = reinterpret_cast<const uint8_t*>(str);

    return { bytes, bytes + strlen(str) };
  }

  /**
   * @brief   Derive a key from a password and salt, reusing an earlier derivation
   */
  static const SecureKey& MakeKey(const char* pw, const std::array<uint8_t, kSaltSize>& salt) {
    using CacheKey = std::pair<std::string, std::array<uint8_t, kSaltSize>>;

    static std::map<CacheKey, SecureKey> cache;

    CacheKey entry{ pw, salt };
    auto it = cache.find(entry);

    if (it == cache.end()) {
      auto key = DeriveKey(std::span<const char>(pw, std::strlen(pw)), salt, MinParams());

      // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
      it = cache.emplace(std::move(entry), std::move(key.value())).first;
    }

    return it->second;
  }

  /**
   * @brief   Create test file
   * @param   path    File path
   * @param   data    File content
   * @param   size    File size
   */
  void Create(const std::string& path, std::vector<uint8_t>& data, size_t size) {
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

    OpenFile(&file, path, "rb");

    if (!file) {
      return;
    }

    const int64_t fsize = GetFileSize(file);

    if (fsize < 0) {
      fclose(file);
      return;
    }

    vec.resize(static_cast<size_t>(fsize));

    size_t res = fread(vec.data(), sizeof(uint8_t), vec.size(), file);

    fclose(file);

    EXPECT_EQ(res, vec.size());
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
  Result res;
  const char* data = "Hello, world!";
  const size_t dsize = strlen(data);
  std::vector<uint8_t> orig = ToBytes(data), copy;

  auto salt = MakeSalt(0xA5);
  const SecureKey& key = MakeKey("password", salt);

  Create(src_path_, orig, dsize);

  /* Encrypt */

  OpenFile(&src, src_path_, "rb");
  OpenFile(&dst, enc_path_, "wb+");

  res = aes.Encrypt(src, dst, key, salt, MinParams());

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
 * @brief   Verify encryption is deterministic, since the nonce is derived from the chunk counter
 */
TEST_F(AesGcmTest, EncryptIsDeterministic) {
  AesGcm aes;
  FILE *src = nullptr, *dst = nullptr;
  const char* data = "Hello, world!";
  const size_t dsize = strlen(data);
  std::vector<uint8_t> orig = ToBytes(data), enc0, enc1;

  auto salt = MakeSalt(0xA5);
  const SecureKey& key = MakeKey("password", salt);

  Create(src_path_, orig, dsize);

  /* First encryption */

  OpenFile(&src, src_path_, "rb");
  OpenFile(&dst, enc_path_, "wb+");

  aes.Encrypt(src, dst, key, salt, MinParams());

  if (src) {
    fclose(src);
  }

  if (dst) {
    fclose(dst);
  }

  /* Second encryption of the same source with the same key and salt */

  OpenFile(&src, src_path_, "rb");
  OpenFile(&dst, dec_path_, "wb+");

  aes.Encrypt(src, dst, key, salt, MinParams());

  if (src) {
    fclose(src);
  }

  if (dst) {
    fclose(dst);
  }

  /* The same key, salt and plaintext must produce byte-identical output */

  Read(enc_path_, enc0);
  Read(dec_path_, enc1);

  EXPECT_FALSE(enc0.empty());
  EXPECT_EQ(enc0, enc1);
}

/**
 * @brief   Verify a reused AesGcm frees its previous context before re-init
 */
TEST_F(AesGcmTest, ReuseFreesPreviousContext) {
  AesGcm aes;
  FILE *src = nullptr, *dst = nullptr;
  Result res0, res1;
  const char* data = "Hello, world!";
  const size_t dsize = strlen(data);
  std::vector<uint8_t> orig = ToBytes(data);

  auto salt = MakeSalt(0xA5);
  const SecureKey& key = MakeKey("password", salt);

  Create(src_path_, orig, dsize);

  /* First encryption - leaves a live context on the object */

  OpenFile(&src, src_path_, "rb");
  OpenFile(&dst, enc_path_, "wb+");

  res0 = aes.Encrypt(src, dst, key, salt, MinParams());

  if (src) {
    fclose(src);
  }

  if (dst) {
    fclose(dst);
  }

  /* Second encryption - EncryptInit must free the previous context */

  OpenFile(&src, src_path_, "rb");
  OpenFile(&dst, dec_path_, "wb+");

  res1 = aes.Encrypt(src, dst, key, salt, MinParams());

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
 * Header Tests
 * ================================================== */

/**
 * @brief   Verify encryption records the magic number and the parameters it was given
 */
TEST_F(AesGcmTest, EncryptWritesHeader) {
  AesGcm aes;
  FILE *src = nullptr, *dst = nullptr;
  const char* data = "Hello, world!";
  const size_t dsize = strlen(data);
  std::vector<uint8_t> orig = ToBytes(data);
  FileHeader header;

  auto salt = MakeSalt(0xA5);
  const SecureKey& key = MakeKey("password", salt);

  Create(src_path_, orig, dsize);

  OpenFile(&src, src_path_, "rb");
  OpenFile(&dst, enc_path_, "wb+");

  EXPECT_EQ(aes.Encrypt(src, dst, key, salt, MinParams()), Result::kSuccess);

  if (src) {
    fclose(src);
  }

  if (dst) {
    fclose(dst);
  }

  /* The header must describe the salt and the parameters the caller derived with */

  OpenFile(&src, enc_path_, "rb");

  ASSERT_NE(src, nullptr);

  EXPECT_EQ(ReadHeader(src, header), HeaderStatus::kOk);

  fclose(src);

  EXPECT_EQ(header.params.time_cost, MinParams().time_cost);
  EXPECT_EQ(header.params.mem_cost, MinParams().mem_cost);
  EXPECT_EQ(header.params.parallelism, MinParams().parallelism);
  EXPECT_EQ(header.salt, salt);
}

/**
 * @brief   Verify a file too small to hold a header is rejected before anything is parsed
 */
TEST_F(AesGcmTest, DecryptRejectsUndersizedFile) {
  AesGcm aes;
  FILE *src = nullptr, *dst = nullptr;
  std::vector<uint8_t> buff(kMinSize - 1, 0x00);
  std::string err;
  Result res;

  auto salt = MakeSalt(0xA5);
  const SecureKey& key = MakeKey("password", salt);

  Create(enc_path_, buff, buff.size());

  aes.SetErrorCallback([&](const char* msg) { err = msg; });

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
  EXPECT_NE(err.find("too small"), std::string::npos);
}

/**
 * @brief   Verify a file written by another tool is rejected on the magic number
 */
TEST_F(AesGcmTest, DecryptRejectsForeignFile) {
  AesGcm aes;
  FILE *src = nullptr, *dst = nullptr;
  std::vector<uint8_t> buff(kMinSize, 0x00);
  std::string err;
  Result res;

  auto salt = MakeSalt(0xA5);
  const SecureKey& key = MakeKey("password", salt);

  Create(enc_path_, buff, buff.size());

  aes.SetErrorCallback([&](const char* msg) { err = msg; });

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
  EXPECT_NE(err.find("Not a FileEncryption file"), std::string::npos);
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
  Result res;
  const char* data = "Hello, world!";
  const size_t dsize = strlen(data);
  std::vector<uint8_t> orig = ToBytes(data);

  auto salt = MakeSalt(0xA5);
  const SecureKey& key0 = MakeKey("password", salt);
  const SecureKey& key1 = MakeKey("asdf1234", salt);

  Create(src_path_, orig, dsize);

  /* Encrypt */

  OpenFile(&src, src_path_, "rb");
  OpenFile(&dst, enc_path_, "wb+");

  aes.Encrypt(src, dst, key0, salt, MinParams());

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
  const size_t dsize = strlen(data);
  Result res;
  std::vector<uint8_t> orig = ToBytes(data), copy;

  auto salt = MakeSalt(0xA5);
  const SecureKey& key = MakeKey("password", salt);

  Create(src_path_, orig, dsize);

  /* Encrypt */

  OpenFile(&src, src_path_, "rb");
  OpenFile(&dst, enc_path_, "wb+");

  aes.Encrypt(src, dst, key, salt, MinParams());

  if (src) {
    fclose(src);
  }

  if (dst) {
    fclose(dst);
  }

  /* Tamper ciphertext */

  Read(enc_path_, copy);

  copy[kHeaderSize] ^= 0xFF;

  Create(enc_path_, copy, copy.size());

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
  Result res;
  const char* data = "Hello, world!";
  const size_t dsize = strlen(data);
  std::vector<uint8_t> orig = ToBytes(data), copy;

  auto salt = MakeSalt(0xA5);
  const SecureKey& key = MakeKey("password", salt);

  Create(src_path_, orig, dsize);

  /* Encrypt */

  OpenFile(&src, src_path_, "rb");
  OpenFile(&dst, enc_path_, "wb+");

  aes.Encrypt(src, dst, key, salt, MinParams());

  if (src) {
    fclose(src);
  }

  if (dst) {
    fclose(dst);
  }

  /* Tamper authentication tag (last byte of the file) */

  Read(enc_path_, copy);

  copy[copy.size() - 1] ^= 0xFF;

  Create(enc_path_, copy, copy.size());

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
  const size_t dsize = 0;
  Result res;

  auto salt = MakeSalt(0xA5);
  const SecureKey& key = MakeKey("password", salt);

  Create(src_path_, orig, dsize);

  /* Encrypt */

  OpenFile(&src, src_path_, "rb");
  OpenFile(&dst, enc_path_, "wb+");

  res = aes.Encrypt(src, dst, key, salt, MinParams());

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
 * @brief   Verify a file of exactly one full chunk works correctly
 */
TEST_F(AesGcmTest, ExactChunkSizeFile) {
  AesGcm aes;
  FILE *src = nullptr, *dst = nullptr;
  Result res;
  std::vector<uint8_t> orig, copy;
  const size_t dsize = kChunkSize;

  auto salt = MakeSalt(0xA5);
  const SecureKey& key = MakeKey("password", salt);

  orig.resize(dsize, uint8_t{ 'a' });

  Create(src_path_, orig, dsize);

  /* Encrypt */

  OpenFile(&src, src_path_, "rb");
  OpenFile(&dst, enc_path_, "wb+");

  res = aes.Encrypt(src, dst, key, salt, MinParams());

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
  Result res;
  std::vector<uint8_t> orig, copy;
  const size_t dsize = 50000;

  auto salt = MakeSalt(0xA5);
  const SecureKey& key = MakeKey("password", salt);

  orig.resize(dsize, uint8_t{ 'a' });

  Create(src_path_, orig, dsize);

  /* Encrypt */

  OpenFile(&src, src_path_, "rb");
  OpenFile(&dst, enc_path_, "wb+");

  res = aes.Encrypt(src, dst, key, salt, MinParams());

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
  const size_t dsize = kChunkSize * 10;
  int cnt = 0, last = -1;

  auto salt = MakeSalt(0xA5);
  const SecureKey& key = MakeKey("password", salt);

  orig.resize(dsize, uint8_t{ 'a' });

  Create(src_path_, orig, dsize);

  /* Encrypt with progress callback */

  OpenFile(&src, src_path_, "rb");
  OpenFile(&dst, enc_path_, "wb+");

  aes.SetProgressCallback([&](int perc) {
    cnt++;

    EXPECT_GE(perc, last);

    last = perc;
  });

  aes.Encrypt(src, dst, key, salt, MinParams());

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
  const size_t dsize = strlen(data);
  std::vector<uint8_t> orig = ToBytes(data);

  auto salt = MakeSalt(0xA5);
  const SecureKey& key0 = MakeKey("password", salt);
  const SecureKey& key1 = MakeKey("asdf1234", salt);

  Create(src_path_, orig, dsize);

  /* Encrypt */

  OpenFile(&src, src_path_, "rb");
  OpenFile(&dst, enc_path_, "wb+");

  aes.Encrypt(src, dst, key0, salt, MinParams());

  if (src) {
    fclose(src);
  }

  if (dst) {
    fclose(dst);
  }

  /* Decrypt with the wrong key and an error callback */

  OpenFile(&src, enc_path_, "rb");
  OpenFile(&dst, dec_path_, "wb+");

  aes.SetErrorCallback([&](const char*) { b = true; });

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
  const char* data = "Hello, world!";
  const size_t dsize = strlen(data);
  std::string captured;
  std::vector<uint8_t> orig = ToBytes(data);

  auto salt = MakeSalt(0xA5);
  const SecureKey& key0 = MakeKey("password", salt);
  const SecureKey& key1 = MakeKey("asdf1234", salt);

  Create(src_path_, orig, dsize);

  /* Encrypt with the correct key */

  OpenFile(&src, src_path_, "rb");
  OpenFile(&dst, enc_path_, "wb+");

  aes.Encrypt(src, dst, key0, salt, MinParams());

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
  Result res;
  std::atomic<bool> cancel{ false };
  std::vector<uint8_t> orig;
  const size_t dsize = kChunkSize * 10;
  int cnt = 0;

  auto salt = MakeSalt(0xA5);
  const SecureKey& key = MakeKey("password", salt);

  orig.resize(dsize, uint8_t{ 'a' });

  Create(src_path_, orig, dsize);

  /* Encrypt and cancel after the second callback */

  OpenFile(&src, src_path_, "rb");
  OpenFile(&dst, enc_path_, "wb+");

  aes.SetCancelFlag(&cancel);

  aes.SetProgressCallback([&](int) {
    cnt++;

    if (cnt >= 2) {
      cancel.store(true, std::memory_order_relaxed);
    }
  });

  res = aes.Encrypt(src, dst, key, salt, MinParams());

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
  Result res;
  std::atomic<bool> cancel{ false };
  std::vector<uint8_t> orig;
  const size_t dsize = kChunkSize * 10;

  auto salt = MakeSalt(0xA5);
  const SecureKey& key = MakeKey("password", salt);

  orig.resize(dsize, uint8_t{ 'a' });

  Create(src_path_, orig, dsize);

  /* Encrypt first to produce a valid ciphertext */

  OpenFile(&src, src_path_, "rb");
  OpenFile(&dst, enc_path_, "wb+");

  aes.Encrypt(src, dst, key, salt, MinParams());

  if (src) {
    fclose(src);
  }

  if (dst) {
    fclose(dst);
  }

  /* Decrypt, cancelling once the write pass is in progress (perc > 50) */

  OpenFile(&src, enc_path_, "rb");
  OpenFile(&dst, dec_path_, "wb+");

  aes.SetCancelFlag(&cancel);

  aes.SetProgressCallback([&](int perc) {
    if (perc > 50) {
      cancel.store(true, std::memory_order_relaxed);
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
  Result res;
  std::string captured;
  std::vector<uint8_t> orig;
  const size_t dsize = kChunkSize * 4;

  auto salt = MakeSalt(0x00);
  const SecureKey& key = MakeKey("password", salt);

  orig.resize(dsize, uint8_t{ 'a' });

  Create(src_path_, orig, dsize);

  /* Encrypt first to produce a valid ciphertext */

  OpenFile(&src, src_path_, "rb");
  OpenFile(&dst, enc_path_, "wb+");

  aes.Encrypt(src, dst, key, salt, MinParams());

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
  Result res = Result::kSuccess;
  std::vector<uint8_t> orig;
  const size_t dsize = kChunkSize * 4;
  int calls = 0;

  auto salt = MakeSalt(0x00);
  const SecureKey& key = MakeKey("password", salt);

  orig.resize(dsize, uint8_t{ 'a' });

  Create(src_path_, orig, dsize);

  /* Encrypt first to produce a valid ciphertext */

  OpenFile(&src, src_path_, "rb");
  OpenFile(&dst, enc_path_, "wb+");

  aes.Encrypt(src, dst, key, salt, MinParams());

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

  aes.SetErrorCallback([&](const char*) {
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
