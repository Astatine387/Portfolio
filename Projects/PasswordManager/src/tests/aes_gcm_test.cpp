/**
 * @file    aes_gcm_test.cpp
 * @brief   Unit tests for AES_GCM class
 * @author  Astatine387
 */

#include "core/aes_gcm.h"

#include <gtest/gtest.h>
#include <openssl/err.h>

#include <algorithm>
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

/* Stand-in for a vault header. The engine attaches no meaning to these bytes; all it promises is that decryption
 * fails unless it is handed the same ones encryption was. */

std::vector<uint8_t> MakeAad(uint8_t fill) {
  return std::vector<uint8_t>(kHeaderSize, fill);
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
  size_t enc_size = kIVSize + dsize + kTagSize;

  std::vector<uint8_t> src(dsize);
  std::vector<uint8_t> enc(enc_size);
  std::vector<uint8_t> dec(dsize);

  memcpy(src.data(), data, dsize);

  auto salt = MakeSalt(0xA5);
  const std::vector<uint8_t> aad = MakeAad(0x5A);
  SecureKey key = MakeKey("password", salt);

  EXPECT_EQ(aes.Encrypt(src.data(), enc.data(), dsize, key, aad), Result::kSuccess);
  EXPECT_EQ(aes.Decrypt(enc.data(), dec.data(), enc_size, key, aad), Result::kSuccess);
  EXPECT_EQ(memcmp(src.data(), dec.data(), dsize), 0);
}

/**
 * @brief   Verify encryption produces different ciphertext each time (fresh IV)
 */
TEST(AesGcmTest, EncryptProducesDifferentOutput) {
  AesGcm aes;

  const char* data = "Hello, world!";
  size_t dsize = strlen(data);
  size_t enc_size = kIVSize + dsize + kTagSize;

  std::vector<uint8_t> src(dsize);
  std::vector<uint8_t> enc0(enc_size);
  std::vector<uint8_t> enc1(enc_size);

  memcpy(src.data(), data, dsize);

  auto salt = MakeSalt(0xA5);
  const std::vector<uint8_t> aad = MakeAad(0x5A);
  SecureKey key = MakeKey("password", salt);

  aes.Encrypt(src.data(), enc0.data(), dsize, key, aad);
  aes.Encrypt(src.data(), enc1.data(), dsize, key, aad);

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
  size_t enc_size = kIVSize + dsize + kTagSize;

  std::vector<uint8_t> src(dsize);
  std::vector<uint8_t> enc0(enc_size);
  std::vector<uint8_t> enc1(enc_size);
  std::vector<uint8_t> dec0(dsize);
  std::vector<uint8_t> dec1(dsize);

  memcpy(src.data(), data, dsize);

  auto salt = MakeSalt(0xA5);
  const std::vector<uint8_t> aad = MakeAad(0x5A);
  SecureKey key = MakeKey("password", salt);

  aes.Encrypt(src.data(), enc0.data(), dsize, key, aad);
  aes.Encrypt(src.data(), enc1.data(), dsize, key, aad);

  /* The IV, now the first thing the buffer holds, must differ between the two writes */

  EXPECT_NE(memcmp(enc0.data(), enc1.data(), kIVSize), 0);

  /* Both ciphertexts must still decrypt back to the plaintext */

  EXPECT_EQ(aes.Decrypt(enc0.data(), dec0.data(), enc_size, key, aad), Result::kSuccess);
  EXPECT_EQ(aes.Decrypt(enc1.data(), dec1.data(), enc_size, key, aad), Result::kSuccess);
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
  size_t enc_size = kIVSize + dsize + kTagSize;

  std::vector<uint8_t> src(dsize);
  std::vector<uint8_t> enc(enc_size);
  std::vector<uint8_t> dec(dsize);

  memcpy(src.data(), data, dsize);

  auto salt = MakeSalt(0xA5);
  const std::vector<uint8_t> aad = MakeAad(0x5A);
  SecureKey key0 = MakeKey("password", salt);
  SecureKey key1 = MakeKey("asdf1234", salt);

  aes.Encrypt(src.data(), enc.data(), dsize, key0, aad);

  EXPECT_EQ(aes.Decrypt(enc.data(), dec.data(), enc_size, key1, aad), Result::kFailure);
}

/**
 * @brief   Verify tampering with ciphertext causes decryption failure
 */
TEST(AesGcmTest, TamperedCiphertext) {
  AesGcm aes;

  const char* data = "Hello, world!";
  size_t dsize = strlen(data);
  size_t enc_size = kIVSize + dsize + kTagSize;

  std::vector<uint8_t> src(dsize);
  std::vector<uint8_t> enc(enc_size);
  std::vector<uint8_t> dec(dsize);

  memcpy(src.data(), data, dsize);

  auto salt = MakeSalt(0xA5);
  const std::vector<uint8_t> aad = MakeAad(0x5A);
  SecureKey key = MakeKey("password", salt);

  aes.Encrypt(src.data(), enc.data(), dsize, key, aad);

  enc[kIVSize] ^= 0x01;

  EXPECT_EQ(aes.Decrypt(enc.data(), dec.data(), enc_size, key, aad), Result::kFailure);
}

/**
 * @brief   Verify tampering with the authentication tag causes decryption failure
 */
TEST(AesGcmTest, TamperedTag) {
  AesGcm aes;

  const char* data = "Hello, world!";
  size_t dsize = strlen(data);
  size_t enc_size = kIVSize + dsize + kTagSize;

  std::vector<uint8_t> src(dsize);
  std::vector<uint8_t> enc(enc_size);
  std::vector<uint8_t> dec(dsize);

  memcpy(src.data(), data, dsize);

  auto salt = MakeSalt(0xA5);
  const std::vector<uint8_t> aad = MakeAad(0x5A);
  SecureKey key = MakeKey("password", salt);

  aes.Encrypt(src.data(), enc.data(), dsize, key, aad);

  enc[enc_size - 1] ^= 0x01;

  EXPECT_EQ(aes.Decrypt(enc.data(), dec.data(), enc_size, key, aad), Result::kFailure);
}

/**
 * @brief   Verify decryption fails under associated data other than what encryption was given
 *
 * The one test that shows the associated data is actually wired into the tag. Everything the vault layer builds on
 * it rests on this: the same key and the same ciphertext, and a single flipped byte outside both of them is enough
 * to refuse the message.
 */
TEST(AesGcmTest, MismatchedAad) {
  AesGcm aes;

  const char* data = "Hello, world!";
  size_t dsize = strlen(data);
  size_t enc_size = kIVSize + dsize + kTagSize;

  std::vector<uint8_t> src(dsize);
  std::vector<uint8_t> enc(enc_size);
  std::vector<uint8_t> dec(dsize);

  memcpy(src.data(), data, dsize);

  auto salt = MakeSalt(0xA5);
  const std::vector<uint8_t> aad = MakeAad(0x5A);
  SecureKey key = MakeKey("password", salt);

  ASSERT_EQ(aes.Encrypt(src.data(), enc.data(), dsize, key, aad), Result::kSuccess);

  std::vector<uint8_t> other = aad;

  other[0] ^= 0x01;

  EXPECT_EQ(aes.Decrypt(enc.data(), dec.data(), enc_size, key, other), Result::kFailure);

  other = aad;
  other[other.size() - 1] ^= 0x80;

  EXPECT_EQ(aes.Decrypt(enc.data(), dec.data(), enc_size, key, other), Result::kFailure);

  /* The same ciphertext still opens under the associated data it was written with */

  EXPECT_EQ(aes.Decrypt(enc.data(), dec.data(), enc_size, key, aad), Result::kSuccess);
  EXPECT_EQ(memcmp(src.data(), dec.data(), dsize), 0);
}

/**
 * @brief   Verify an empty associated data round-trips, and does not interchange with a non-empty one
 */
TEST(AesGcmTest, EmptyAad) {
  AesGcm aes;

  const char* data = "Hello, world!";
  size_t dsize = strlen(data);
  size_t enc_size = kIVSize + dsize + kTagSize;

  std::vector<uint8_t> src(dsize);
  std::vector<uint8_t> enc(enc_size);
  std::vector<uint8_t> dec(dsize);

  memcpy(src.data(), data, dsize);

  auto salt = MakeSalt(0xA5);
  const std::vector<uint8_t> aad = MakeAad(0x5A);
  SecureKey key = MakeKey("password", salt);

  EXPECT_EQ(aes.Encrypt(src.data(), enc.data(), dsize, key, std::span<const uint8_t>{}), Result::kSuccess);
  EXPECT_EQ(aes.Decrypt(enc.data(), dec.data(), enc_size, key, std::span<const uint8_t>{}), Result::kSuccess);
  EXPECT_EQ(memcmp(src.data(), dec.data(), dsize), 0);

  /* Nothing authenticated is not the same as something authenticated */

  EXPECT_EQ(aes.Decrypt(enc.data(), dec.data(), enc_size, key, aad), Result::kFailure);
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
  size_t enc_size = kIVSize + dsize + kTagSize;

  std::vector<uint8_t> src(dsize);
  std::vector<uint8_t> enc(enc_size);
  std::vector<uint8_t> dec(dsize);

  auto salt = MakeSalt(0xA5);
  const std::vector<uint8_t> aad = MakeAad(0x5A);
  SecureKey key = MakeKey("password", salt);

  EXPECT_EQ(aes.Encrypt(src.data(), enc.data(), dsize, key, aad), Result::kSuccess);
  EXPECT_EQ(aes.Decrypt(enc.data(), dec.data(), enc_size, key, aad), Result::kSuccess);
}

/**
 * @brief   Verify encryption and decryption works with single byte
 */
TEST(AesGcmTest, SingleByte) {
  AesGcm aes;

  size_t dsize = 1;
  size_t enc_size = kIVSize + dsize + kTagSize;

  uint8_t src = 0x00;
  std::vector<uint8_t> enc(enc_size);
  uint8_t dec = 0xFF;

  auto salt = MakeSalt(0xA5);
  const std::vector<uint8_t> aad = MakeAad(0x5A);
  SecureKey key = MakeKey("password", salt);

  EXPECT_EQ(aes.Encrypt(&src, enc.data(), dsize, key, aad), Result::kSuccess);
  EXPECT_EQ(aes.Decrypt(enc.data(), &dec, enc_size, key, aad), Result::kSuccess);
  EXPECT_EQ(dec, src);
}

/**
 * @brief   Verify encryption and decryption works with large data
 */
TEST(AesGcmTest, LargeData) {
  AesGcm aes;

  size_t dsize = 1024ULL * 1024;  // 1 MiB
  size_t enc_size = kIVSize + dsize + kTagSize;

  std::vector<uint8_t> src(dsize, 0x00);
  std::vector<uint8_t> enc(enc_size);
  std::vector<uint8_t> dec(dsize);

  auto salt = MakeSalt(0xA5);
  const std::vector<uint8_t> aad = MakeAad(0x5A);
  SecureKey key = MakeKey("password", salt);

  EXPECT_EQ(aes.Encrypt(src.data(), enc.data(), dsize, key, aad), Result::kSuccess);
  EXPECT_EQ(aes.Decrypt(enc.data(), dec.data(), enc_size, key, aad), Result::kSuccess);
  EXPECT_EQ(memcmp(src.data(), dec.data(), dsize), 0);
}

/* ==================================================
 * Input Validation Tests
 * ================================================== */

/**
 * @brief   Verify decryption refuses a buffer too short to hold an initial vector and tag
 *
 * The tag is read from src + size - kTagSize before anything has looked at the size, and that subtraction is over
 * size_t, so it wraps instead of going negative and the read lands nowhere near the allocation. Every buffer below
 * is allocated at the length it claims, leaving ASan something to report should the check ever go away.
 */
TEST(AesGcmTest, DecryptRejectsBufferSmallerThanIvAndTag) {
  AesGcm aes;

  auto salt = MakeSalt(0xA5);
  const std::vector<uint8_t> aad = MakeAad(0x5A);
  SecureKey key = MakeKey("password", salt);

  /* Nothing at all, one byte short of the tag, and one byte short of the tag and the initial vector together */

  for (const size_t dsize : { size_t{ 0 }, size_t{ 15 }, size_t{ 27 } }) {
    /* A zero-length allocation may hand back a null pointer, which would trip the null check and leave the size
     * check untested, so the buffers are never shorter than a byte */

    std::vector<uint8_t> src(std::max<size_t>(dsize, 1));
    std::vector<uint8_t> dec(std::max<size_t>(dsize, 1));

    EXPECT_EQ(aes.Decrypt(src.data(), dec.data(), dsize, key, aad), Result::kFailure) << "size = " << dsize;
  }
}

/**
 * @brief   Verify decryption refuses a null source buffer
 */
TEST(AesGcmTest, DecryptRejectsNullSource) {
  AesGcm aes;

  size_t dsize = 13;
  size_t enc_size = kIVSize + dsize + kTagSize;

  std::vector<uint8_t> dec(dsize);

  auto salt = MakeSalt(0xA5);
  const std::vector<uint8_t> aad = MakeAad(0x5A);
  SecureKey key = MakeKey("password", salt);

  /* The size clears the framing with room to spare, so it is the missing source and nothing else being refused */

  EXPECT_EQ(aes.Decrypt(nullptr, dec.data(), enc_size, key, aad), Result::kFailure);
}

/**
 * @brief   Verify encryption refuses a null destination buffer
 */
TEST(AesGcmTest, EncryptRejectsNullDestination) {
  AesGcm aes;

  const char* data = "Hello, world!";
  size_t dsize = strlen(data);
  size_t empty = 0;

  std::vector<uint8_t> src(dsize);

  memcpy(src.data(), data, dsize);

  auto salt = MakeSalt(0xA5);
  const std::vector<uint8_t> aad = MakeAad(0x5A);
  SecureKey key = MakeKey("password", salt);

  EXPECT_EQ(aes.Encrypt(src.data(), nullptr, dsize, key, aad), Result::kFailure);

  /* Refused at a size of zero as well, since the initial vector and the tag are written whatever the plaintext is */

  EXPECT_EQ(aes.Encrypt(src.data(), nullptr, empty, key, aad), Result::kFailure);
}

/**
 * @brief   Verify an empty plaintext is accepted with no source to read and no destination to write
 *
 * EmptyData passes the .data() of empty vectors, which is a null pointer on this implementation and need not be on
 * another, so what that test covers is left to chance. This states it outright, in both directions: a plaintext of
 * length zero is accepted with a null source, and the framing it decrypts back through is accepted with a null
 * destination.
 */
TEST(AesGcmTest, EncryptAcceptsNullSourceWhenSizeIsZero) {
  AesGcm aes;

  size_t dsize = 0;
  size_t enc_size = kIVSize + dsize + kTagSize;

  std::vector<uint8_t> enc(enc_size);

  auto salt = MakeSalt(0xA5);
  const std::vector<uint8_t> aad = MakeAad(0x5A);
  SecureKey key = MakeKey("password", salt);

  EXPECT_EQ(aes.Encrypt(nullptr, enc.data(), dsize, key, aad), Result::kSuccess);
  EXPECT_EQ(aes.Decrypt(enc.data(), nullptr, enc_size, key, aad), Result::kSuccess);
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
  size_t enc_size = kIVSize + dsize + kTagSize;

  std::vector<uint8_t> src(dsize);
  std::vector<uint8_t> enc(enc_size);
  std::vector<uint8_t> dec(dsize);

  memcpy(src.data(), data, dsize);

  auto salt = MakeSalt(0xA5);
  const std::vector<uint8_t> aad = MakeAad(0x5A);
  SecureKey key0 = MakeKey("password", salt);
  SecureKey key1 = MakeKey("asdf1234", salt);

  aes.Encrypt(src.data(), enc.data(), dsize, key0, aad);

  aes.SetErrorCallback([&](const char*) { cb_called = true; });

  aes.Decrypt(enc.data(), dec.data(), enc_size, key1, aad);

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
  size_t enc_size = kIVSize + dsize + kTagSize;

  std::vector<uint8_t> src(dsize);
  std::vector<uint8_t> enc(enc_size);
  std::vector<uint8_t> dec(dsize);

  memcpy(src.data(), data, dsize);

  auto salt = MakeSalt(0xA5);
  const std::vector<uint8_t> aad = MakeAad(0x5A);
  SecureKey key0 = MakeKey("password", salt);
  SecureKey key1 = MakeKey("asdf1234", salt);

  aes.Encrypt(src.data(), enc.data(), dsize, key0, aad);

  aes.SetErrorCallback([&](const char* msg) {
    called = true;
    captured = msg;
  });

  /* Seed the OpenSSL error queue, then fail decryption with the wrong key */

  ERR_clear_error();
  ERR_raise(ERR_LIB_USER, ERR_R_INTERNAL_ERROR);

  aes.Decrypt(enc.data(), dec.data(), enc_size, key1, aad);

  EXPECT_TRUE(called);
  EXPECT_NE(captured.find(" -> "), std::string::npos);
}
