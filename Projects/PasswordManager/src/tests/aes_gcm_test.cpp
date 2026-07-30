/**
 * @file    aes_gcm_test.cpp
 * @brief   Unit tests for AES_GCM class
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

#include "common/constants.h"
#include "core/secure_key.h"

namespace {

/* Small Argon2id parameters keep the key derivation fast for tests */

KdfParams FastParams() {
  return KdfParams{ .time_cost = 1, .mem_cost = 8, .parallelism = 1 };
}

std::array<uint8_t, kSaltSize> MakeSalt(uint8_t fill) {
  std::array<uint8_t, kSaltSize> salt{};
  salt.fill(fill);
  return salt;
}

SecureKey MakeKey(const char* pw, const std::array<uint8_t, kSaltSize>& salt) {
  auto key = DeriveKey(std::span<const char>(pw, std::strlen(pw)), salt, FastParams());
  return std::move(key.value());  // NOLINT(bugprone-unchecked-optional-access)
}

}  // namespace

/* ==================================================
 * Encryption/Decryption Tests
 * ================================================== */

/**
 * @brief   Verify encryption and decryption round-trip preserves data
 */
TEST(AesGcmTest, EncryptDecryptBasic) {
  AesGcm aes;

  const char* data = "Hello, world!";
  size_t dsize = strlen(data);
  size_t enc_size = kSaltSize + kIVSize + dsize + kTagSize;

  std::vector<uint8_t> src(dsize);
  std::vector<uint8_t> enc(enc_size);
  std::vector<uint8_t> dec(dsize);

  memcpy(src.data(), data, dsize);

  auto salt = MakeSalt(0xA5);
  SecureKey key = MakeKey("password", salt);

  EXPECT_EQ(aes.Encrypt(src.data(), enc.data(), dsize, key, salt), Result::kSuccess);
  EXPECT_EQ(aes.Decrypt(enc.data(), dec.data(), enc_size, key), Result::kSuccess);
  EXPECT_EQ(memcmp(src.data(), dec.data(), dsize), 0);
}

/**
 * @brief   Verify encryption produces different ciphertext each time (fresh IV)
 */
TEST(AesGcmTest, EncryptProducesDifferentOutput) {
  AesGcm aes;

  const char* data = "Hello, world!";
  size_t dsize = strlen(data);
  size_t enc_size = kSaltSize + kIVSize + dsize + kTagSize;

  std::vector<uint8_t> src(dsize);
  std::vector<uint8_t> enc0(enc_size);
  std::vector<uint8_t> enc1(enc_size);

  memcpy(src.data(), data, dsize);

  auto salt = MakeSalt(0xA5);
  SecureKey key = MakeKey("password", salt);

  aes.Encrypt(src.data(), enc0.data(), dsize, key, salt);
  aes.Encrypt(src.data(), enc1.data(), dsize, key, salt);

  EXPECT_NE(memcmp(enc0.data(), enc1.data(), enc_size), 0);
}

/**
 * @brief   Verify a fresh IV is generated on every encrypt under a fixed key,
 *          yet both ciphertexts decrypt correctly (D3)
 */
TEST(AesGcmTest, FreshIvPerEncrypt) {
  AesGcm aes;

  const char* data = "Hello, world!";
  size_t dsize = strlen(data);
  size_t enc_size = kSaltSize + kIVSize + dsize + kTagSize;

  std::vector<uint8_t> src(dsize);
  std::vector<uint8_t> enc0(enc_size);
  std::vector<uint8_t> enc1(enc_size);
  std::vector<uint8_t> dec0(dsize);
  std::vector<uint8_t> dec1(dsize);

  memcpy(src.data(), data, dsize);

  auto salt = MakeSalt(0xA5);
  SecureKey key = MakeKey("password", salt);

  aes.Encrypt(src.data(), enc0.data(), dsize, key, salt);
  aes.Encrypt(src.data(), enc1.data(), dsize, key, salt);

  /* The IV (written after the salt) must differ between the two writes */

  EXPECT_NE(memcmp(enc0.data() + kSaltSize, enc1.data() + kSaltSize, kIVSize), 0);

  /* Both ciphertexts must still decrypt back to the plaintext */

  EXPECT_EQ(aes.Decrypt(enc0.data(), dec0.data(), enc_size, key), Result::kSuccess);
  EXPECT_EQ(aes.Decrypt(enc1.data(), dec1.data(), enc_size, key), Result::kSuccess);
  EXPECT_EQ(memcmp(src.data(), dec0.data(), dsize), 0);
  EXPECT_EQ(memcmp(src.data(), dec1.data(), dsize), 0);
}

/**
 * @brief   Verify decryption with the wrong key fails
 */
TEST(AesGcmTest, DecryptWrongKey) {
  AesGcm aes;

  const char* data = "Hello, world!";
  size_t dsize = strlen(data);
  size_t enc_size = kSaltSize + kIVSize + dsize + kTagSize;

  std::vector<uint8_t> src(dsize);
  std::vector<uint8_t> enc(enc_size);
  std::vector<uint8_t> dec(dsize);

  memcpy(src.data(), data, dsize);

  auto salt = MakeSalt(0xA5);
  SecureKey key0 = MakeKey("password", salt);
  SecureKey key1 = MakeKey("asdf1234", salt);

  aes.Encrypt(src.data(), enc.data(), dsize, key0, salt);

  EXPECT_EQ(aes.Decrypt(enc.data(), dec.data(), enc_size, key1), Result::kFailure);
}

/**
 * @brief   Verify tampering with ciphertext causes decryption failure
 */
TEST(AesGcmTest, TamperedCiphertext) {
  AesGcm aes;

  const char* data = "Hello, world!";
  size_t dsize = strlen(data);
  size_t enc_size = kSaltSize + kIVSize + dsize + kTagSize;

  std::vector<uint8_t> src(dsize);
  std::vector<uint8_t> enc(enc_size);
  std::vector<uint8_t> dec(dsize);

  memcpy(src.data(), data, dsize);

  auto salt = MakeSalt(0xA5);
  SecureKey key = MakeKey("password", salt);

  aes.Encrypt(src.data(), enc.data(), dsize, key, salt);

  enc[kSaltSize + kIVSize] ^= 0x01;

  EXPECT_EQ(aes.Decrypt(enc.data(), dec.data(), enc_size, key), Result::kFailure);
}

/**
 * @brief   Verify tampering with the authentication tag causes decryption failure
 */
TEST(AesGcmTest, TamperedTag) {
  AesGcm aes;

  const char* data = "Hello, world!";
  size_t dsize = strlen(data);
  size_t enc_size = kSaltSize + kIVSize + dsize + kTagSize;

  std::vector<uint8_t> src(dsize);
  std::vector<uint8_t> enc(enc_size);
  std::vector<uint8_t> dec(dsize);

  memcpy(src.data(), data, dsize);

  auto salt = MakeSalt(0xA5);
  SecureKey key = MakeKey("password", salt);

  aes.Encrypt(src.data(), enc.data(), dsize, key, salt);

  enc[enc_size - 1] ^= 0x01;

  EXPECT_EQ(aes.Decrypt(enc.data(), dec.data(), enc_size, key), Result::kFailure);
}

/* ==================================================
 * Edge Case Tests
 * ================================================== */

/**
 * @brief   Verify encryption and decryption works with empty data
 */
TEST(AesGcmTest, EmptyData) {
  AesGcm aes;

  size_t dsize = 0;
  size_t enc_size = kSaltSize + kIVSize + dsize + kTagSize;

  std::vector<uint8_t> src(dsize);
  std::vector<uint8_t> enc(enc_size);
  std::vector<uint8_t> dec(dsize);

  auto salt = MakeSalt(0xA5);
  SecureKey key = MakeKey("password", salt);

  EXPECT_EQ(aes.Encrypt(src.data(), enc.data(), dsize, key, salt), Result::kSuccess);
  EXPECT_EQ(aes.Decrypt(enc.data(), dec.data(), enc_size, key), Result::kSuccess);
}

/**
 * @brief   Verify encryption and decryption works with single byte
 */
TEST(AesGcmTest, SingleByte) {
  AesGcm aes;

  size_t dsize = 1;
  size_t enc_size = kSaltSize + kIVSize + dsize + kTagSize;

  uint8_t src = 0x00;
  std::vector<uint8_t> enc(enc_size);
  uint8_t dec = 0xFF;

  auto salt = MakeSalt(0xA5);
  SecureKey key = MakeKey("password", salt);

  EXPECT_EQ(aes.Encrypt(&src, enc.data(), dsize, key, salt), Result::kSuccess);
  EXPECT_EQ(aes.Decrypt(enc.data(), &dec, enc_size, key), Result::kSuccess);
  EXPECT_EQ(dec, src);
}

/**
 * @brief   Verify encryption and decryption works with large data
 */
TEST(AesGcmTest, LargeData) {
  AesGcm aes;

  size_t dsize = 1024ULL * 1024;  // 1 MiB
  size_t enc_size = kSaltSize + kIVSize + dsize + kTagSize;

  std::vector<uint8_t> src(dsize, 0x00);
  std::vector<uint8_t> enc(enc_size);
  std::vector<uint8_t> dec(dsize);

  auto salt = MakeSalt(0xA5);
  SecureKey key = MakeKey("password", salt);

  EXPECT_EQ(aes.Encrypt(src.data(), enc.data(), dsize, key, salt), Result::kSuccess);
  EXPECT_EQ(aes.Decrypt(enc.data(), dec.data(), enc_size, key), Result::kSuccess);
  EXPECT_EQ(memcmp(src.data(), dec.data(), dsize), 0);
}

/* ==================================================
 * Error Callback Test
 * ================================================== */

/**
 * @brief   Verify error callback is invoked on decryption failure
 */
TEST(AesGcmTest, ErrorCallback) {
  AesGcm aes;
  bool cb_called = false;

  const char* data = "Hello, world!";
  size_t dsize = strlen(data);
  size_t enc_size = kSaltSize + kIVSize + dsize + kTagSize;

  std::vector<uint8_t> src(dsize);
  std::vector<uint8_t> enc(enc_size);
  std::vector<uint8_t> dec(dsize);

  memcpy(src.data(), data, dsize);

  auto salt = MakeSalt(0xA5);
  SecureKey key0 = MakeKey("password", salt);
  SecureKey key1 = MakeKey("asdf1234", salt);

  aes.Encrypt(src.data(), enc.data(), dsize, key0, salt);

  aes.SetErrorCallback([&](const char*) { cb_called = true; });

  aes.Decrypt(enc.data(), dec.data(), enc_size, key1);

  EXPECT_TRUE(cb_called);
}

/**
 * @brief   Verify ReportError formats and appends queued OpenSSL errors
 */
TEST(AesGcmTest, ErrorCallbackFormatsQueue) {
  AesGcm aes;
  bool called = false;
  std::string captured;

  const char* data = "Hello, world!";
  size_t dsize = strlen(data);
  size_t enc_size = kSaltSize + kIVSize + dsize + kTagSize;

  std::vector<uint8_t> src(dsize);
  std::vector<uint8_t> enc(enc_size);
  std::vector<uint8_t> dec(dsize);

  memcpy(src.data(), data, dsize);

  auto salt = MakeSalt(0xA5);
  SecureKey key0 = MakeKey("password", salt);
  SecureKey key1 = MakeKey("asdf1234", salt);

  aes.Encrypt(src.data(), enc.data(), dsize, key0, salt);

  aes.SetErrorCallback([&](const char* msg) {
    called = true;
    captured = msg;
  });

  /* Seed the OpenSSL error queue, then fail decryption with the wrong key */

  ERR_clear_error();
  ERR_raise(ERR_LIB_USER, ERR_R_INTERNAL_ERROR);

  aes.Decrypt(enc.data(), dec.data(), enc_size, key1);

  EXPECT_TRUE(called);
  EXPECT_NE(captured.find(" -> "), std::string::npos);
}
