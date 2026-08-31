/**
 * @file    kat_test.cpp
 * @brief   Known-answer tests for the AES-256-GCM and Argon2id primitives
 * @author  Astatine387
 *
 * Every value in this file is transcribed from official sources:
 *  - NIST CAVP "GCM Test Vectors", archive gcmtestvectors.zip, file gcmEncryptExtIV256.rsp (CAVS 14.0, generated
 *    2012-08-31), published at https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program
 *  - RFC 9106 section 5.3, "Argon2id Test Vectors"
 */

#include <argon2.h>
#include <gtest/gtest.h>
#include <openssl/evp.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string_view>
#include <vector>

#include "common/constants.h"

namespace {

/* ==================================================
 * Test vector data
 * ================================================== */

/**
 * @struct  GcmVector
 * @brief   One AES-256-GCM encryption test vector
 */
struct GcmVector {
  std::string_view name;  // Section and count the vector was taken from
  std::string_view key;   // 32-byte key
  std::string_view iv;    // 12-byte initial vector
  std::string_view aad;   // Associated data, possibly empty
  std::string_view pt;    // Plaintext, possibly empty
  std::string_view ct;    // Expected ciphertext
  std::string_view tag;   // Expected 16-byte authentication tag
};

/* Transcribed verbatim from gcmEncryptExtIV256.rsp */

constexpr std::array<GcmVector, 5> kGcmVectors{
  GcmVector{ .name = "PTlen=0 AADlen=0 Count=0",
             .key = "b52c505a37d78eda5dd34f20c22540ea1b58963cf8e5bf8ffa85f9f2492505b4",
             .iv = "516c33929df5a3284ff463d7",
             .aad = "",
             .pt = "",
             .ct = "",
             .tag = "bdc1ac884d332457a1d2664f168c76f0" },
  GcmVector{ .name = "PTlen=128 AADlen=0 Count=0",
             .key = "31bdadd96698c204aa9ce1448ea94ae1fb4a9a0b3c9d773b51bb1822666b8f22",
             .iv = "0d18e06c7c725ac9e362e1ce",
             .aad = "",
             .pt = "2db5168e932556f8089a0622981d017d",
             .ct = "fa4362189661d163fcd6a56d8bf0405a",
             .tag = "d636ac1bbedd5cc3ee727dc2ab4a9489" },
  GcmVector{ .name = "PTlen=128 AADlen=128 Count=0",
             .key = "92e11dcdaa866f5ce790fd24501f92509aacf4cb8b1339d50c9c1240935dd08b",
             .iv = "ac93a1a6145299bde902f21a",
             .aad = "1e0889016f67601c8ebea4943bc23ad6",
             .pt = "2d71bcfa914e4ac045b2aa60955fad24",
             .ct = "8995ae2e6df3dbf96fac7b7137bae67f",
             .tag = "eca5aa77d51d4a0a14d9c51e1da474ab" },
  GcmVector{ .name = "PTlen=104 AADlen=160 Count=1",
             .key = "97431e565e8370a4879de962746a2fd67eca868b1c8e51eece2c1f94f74af407",
             .iv = "17fb63066e2726d282ecc610",
             .aad = "78e7374da7c77be5938de8dd76cf0308618306a9",
             .pt = "e21629cc973fbe40176e621d9d",
             .ct = "80dbd469de480389ba6c2fca52",
             .tag = "4e284abb8b4f9f13c7497ae56df05fa5" },
  GcmVector{ .name = "PTlen=408 AADlen=720 Count=2",
             .key = "c277df045d0a1a3956958f271055c229d2634427b1d73e99d54920da69f72e01",
             .iv = "79e24f84bc77a21a6cb14ee2",
             .aad = "ca09282238d492029afbd30ea9b4aa9d448d77b4b41a791c35ebe3f8e5034ac71210117a843fae647cea020712c27e"
                    "5c8f85acf933d5e28430c7770862d8dbb197cbbcfe49dd63f6aa05fbd13e32c459342698dfee5935c7c321",
             .pt = "5ca68d858cc30b1cb0514c4e9de98e1a1a835df401f69e9ec6f1bcb1158f09114dff551683b3827457f77e17a7097b"
                   "1ea69eac",
             .ct = "5c5223c8eda59a8dc28b08e6c21482a46e5d84d32c7050bf144fc57f4e8094de133198da7b4b8398b167204aff837d"
                   "a15d9ab2",
             .tag = "378885950a4491bee3cd681d3c957b9a" },
};

/* RFC 9106 section 5.3 */

constexpr uint32_t kRfcTagLen = 32;      // "Tag length: 32 bytes"
constexpr uint32_t kRfcMemCost = 32;     // "Memory: 32 KiB"
constexpr uint32_t kRfcTimeCost = 3;     // "Passes: 3"
constexpr uint32_t kRfcParallelism = 4;  // "Parallelism: 4 lanes"

constexpr uint8_t kRfcPasswordByte = 0x01;  // "Password[32]: 01 01 ..."
constexpr uint8_t kRfcSaltByte = 0x02;      // "Salt[16]: 02 02 ..."
constexpr uint8_t kRfcSecretByte = 0x03;    // "Secret[8]: 03 03 ..."
constexpr uint8_t kRfcAdByte = 0x04;        // "Associated data[12]: 04 04 ..."

constexpr size_t kRfcPasswordSize = 32;
constexpr size_t kRfcSaltSize = 16;
constexpr size_t kRfcSecretSize = 8;
constexpr size_t kRfcAdSize = 12;

constexpr std::array<uint8_t, kRfcTagLen> kRfcTag{ 0x0d, 0x64, 0x0d, 0xf5, 0x8d, 0x78, 0x76, 0x6c, 0x08, 0xc0, 0x37,
                                                   0xa3, 0x4a, 0x8b, 0x53, 0xc9, 0xd0, 0x1e, 0xf0, 0x45, 0x2d, 0x75,
                                                   0xb6, 0x5e, 0xb5, 0x25, 0x20, 0xe9, 0x6b, 0x01, 0xe6, 0x59 };

/* ==================================================
 * Helper functions
 * ================================================== */

constexpr size_t kAesBlockSize = 16;
constexpr uint8_t kBadDigit = 0xFF;  // Sentinel returned for a character that is not a hex digit

/**
 * @brief   Convert one hexadecimal character to its value
 * @param   chr     Character to convert
 * @return  Value in 0..15, or kBadDigit when the character is not a hex digit
 */
uint8_t HexDigit(char chr) {
  if ('0' <= chr && chr <= '9') {
    return static_cast<uint8_t>(chr - '0');
  }

  if ('a' <= chr && chr <= 'f') {
    return static_cast<uint8_t>(chr - 'a' + 10);
  }

  if ('A' <= chr && chr <= 'F') {
    return static_cast<uint8_t>(chr - 'A' + 10);
  }

  return kBadDigit;
}

/**
 * @brief   Convert a hexadecimal string to bytes
 * @param   hex   String of hex digit pairs, may be empty
 * @return  Decoded bytes
 */
std::vector<uint8_t> FromHex(std::string_view hex) {
  std::vector<uint8_t> res;

  EXPECT_EQ(hex.size() % 2, 0U);

  res.reserve(hex.size() / 2);

  for (size_t i = 0; i + 1 < hex.size(); i += 2) {
    const uint8_t h = HexDigit(hex[i]);
    const uint8_t l = HexDigit(hex[i + 1]);

    EXPECT_NE(h, kBadDigit);
    EXPECT_NE(l, kBadDigit);

    res.push_back(static_cast<uint8_t>((h << 4) | l));
  }

  return res;
}

using CtxPtr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

/**
 * @brief   Create an AES-256-GCM context with the key and initial vector already set
 * @param   key   32-byte key
 * @param   iv    Initial vector
 * @param   mode  Direction the context is built for
 * @return  Context on success, a null holder on failure
 */
CtxPtr MakeCtx(std::span<const uint8_t> key, std::span<const uint8_t> iv, CryptoMode mode) {
  CtxPtr ctx(EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_free);

  if (!ctx) {
    return { nullptr, &EVP_CIPHER_CTX_free };
  }

  const auto init = mode == CryptoMode::kEncrypt ? &EVP_EncryptInit_ex : &EVP_DecryptInit_ex;

  if (init(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
    return { nullptr, &EVP_CIPHER_CTX_free };
  }

  if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()), nullptr) != 1) {
    return { nullptr, &EVP_CIPHER_CTX_free };
  }

  if (init(ctx.get(), nullptr, nullptr, key.data(), iv.data()) != 1) {
    return { nullptr, &EVP_CIPHER_CTX_free };
  }

  return ctx;
}

/**
 * @brief   Encrypt one buffer with AES-256-GCM
 * @param   vec     Vector supplying key, IV, AAD and plaintext
 * @param   ct      Destination for the ciphertext
 * @param   tag     Destination for the authentication tag
 * @return  kSuccess on success, kFailure on failure
 */
Result GcmEncrypt(const GcmVector& vec, std::vector<uint8_t>& ct, std::vector<uint8_t>& tag) {
  const std::vector<uint8_t> key = FromHex(vec.key);
  const std::vector<uint8_t> iv = FromHex(vec.iv);
  const std::vector<uint8_t> aad = FromHex(vec.aad);
  const std::vector<uint8_t> pt = FromHex(vec.pt);

  CtxPtr ctx = MakeCtx(key, iv, CryptoMode::kEncrypt);

  if (!ctx) {
    return Result::kFailure;
  }

  int len = 0;

  if (!aad.empty() && EVP_EncryptUpdate(ctx.get(), nullptr, &len, aad.data(), static_cast<int>(aad.size())) != 1) {
    return Result::kFailure;
  }

  ct.assign(pt.size(), 0);

  if (!pt.empty() && EVP_EncryptUpdate(ctx.get(), ct.data(), &len, pt.data(), static_cast<int>(pt.size())) != 1) {
    return Result::kFailure;
  }

  std::array<uint8_t, kAesBlockSize> final_block{};

  if (EVP_EncryptFinal_ex(ctx.get(), final_block.data(), &len) != 1) {
    return Result::kFailure;
  }

  tag.assign(kTagSize, 0);

  if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, static_cast<int>(tag.size()), tag.data()) != 1) {
    return Result::kFailure;
  }

  return Result::kSuccess;
}

/**
 * @brief   Decrypt one buffer with AES-256-GCM and verify its tag
 * @param   vec     Vector supplying key, initial vector, associated data and ciphertext
 * @param   tag     Authentication tag to verify against
 * @param   pt      Destination for the recovered plaintext
 * @return  kSuccess when the tag verifies, kFailure otherwise
 */
Result GcmDecrypt(const GcmVector& vec, std::span<const uint8_t> tag, std::vector<uint8_t>& pt) {
  const std::vector<uint8_t> key = FromHex(vec.key);
  const std::vector<uint8_t> iv = FromHex(vec.iv);
  const std::vector<uint8_t> aad = FromHex(vec.aad);
  const std::vector<uint8_t> ct = FromHex(vec.ct);

  CtxPtr ctx = MakeCtx(key, iv, CryptoMode::kDecrypt);

  if (!ctx) {
    return Result::kFailure;
  }

  int len = 0;

  if (!aad.empty() && EVP_DecryptUpdate(ctx.get(), nullptr, &len, aad.data(), static_cast<int>(aad.size())) != 1) {
    return Result::kFailure;
  }

  pt.assign(ct.size(), 0);

  if (!ct.empty() && EVP_DecryptUpdate(ctx.get(), pt.data(), &len, ct.data(), static_cast<int>(ct.size())) != 1) {
    return Result::kFailure;
  }

  auto* tag_ptr = const_cast<uint8_t*>(tag.data());  // NOLINT(cppcoreguidelines-pro-type-const-cast)

  if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag.size()), tag_ptr) != 1) {
    return Result::kFailure;
  }

  std::array<uint8_t, kAesBlockSize> final_block{};

  if (EVP_DecryptFinal_ex(ctx.get(), final_block.data(), &len) != 1) {
    return Result::kFailure;
  }

  return Result::kSuccess;
}

}  // namespace

/* ==================================================
 * AES-256-GCM Known-Answer Tests
 * ================================================== */

/**
 * @brief   Verify every NIST CAVP vector reproduces its exact ciphertext and tag
 */
TEST(KatTest, NistCavpAes256GcmEncrypt) {
  for (const GcmVector& vec : kGcmVectors) {
    SCOPED_TRACE(testing::Message() << "gcmEncryptExtIV256.rsp " << vec.name);

    std::vector<uint8_t> ct;
    std::vector<uint8_t> tag;

    ASSERT_EQ(GcmEncrypt(vec, ct, tag), Result::kSuccess);
    EXPECT_EQ(ct, FromHex(vec.ct));
    EXPECT_EQ(tag, FromHex(vec.tag));
  }
}

/**
 * @brief   Verify every NIST CAVP vector decrypts back to its plaintext under its own tag
 */
TEST(KatTest, NistCavpAes256GcmDecrypt) {
  for (const GcmVector& vec : kGcmVectors) {
    SCOPED_TRACE(testing::Message() << "gcmEncryptExtIV256.rsp " << vec.name);

    const std::vector<uint8_t> tag = FromHex(vec.tag);
    std::vector<uint8_t> pt;

    ASSERT_EQ(GcmDecrypt(vec, tag, pt), Result::kSuccess);
    EXPECT_EQ(pt, FromHex(vec.pt));
  }
}

/* ==================================================
 * Argon2id Known-Answer Test
 * ================================================== */

/**
 * @brief   Verify the RFC 9106 section 5.3 Argon2id vector reproduces its exact 32-byte tag
 */
TEST(KatTest, Rfc9106Argon2id) {
  std::array<uint8_t, kRfcTagLen> out{};
  std::array<uint8_t, kRfcPasswordSize> pwd{};
  std::array<uint8_t, kRfcSaltSize> salt{};
  std::array<uint8_t, kRfcSecretSize> secret{};
  std::array<uint8_t, kRfcAdSize> ad{};

  pwd.fill(kRfcPasswordByte);
  salt.fill(kRfcSaltByte);
  secret.fill(kRfcSecretByte);
  ad.fill(kRfcAdByte);

  argon2_context ctx{};

  ctx.out = out.data();
  ctx.outlen = kRfcTagLen;

  ctx.pwd = pwd.data();
  ctx.pwdlen = static_cast<uint32_t>(pwd.size());

  ctx.salt = salt.data();
  ctx.saltlen = static_cast<uint32_t>(salt.size());

  ctx.secret = secret.data();
  ctx.secretlen = static_cast<uint32_t>(secret.size());

  ctx.ad = ad.data();
  ctx.adlen = static_cast<uint32_t>(ad.size());

  ctx.t_cost = kRfcTimeCost;
  ctx.m_cost = kRfcMemCost;
  ctx.lanes = kRfcParallelism;
  ctx.threads = kRfcParallelism;
  ctx.version = ARGON2_VERSION_13;
  ctx.allocate_cbk = nullptr;
  ctx.free_cbk = nullptr;
  ctx.flags = ARGON2_DEFAULT_FLAGS;

  ASSERT_EQ(argon2id_ctx(&ctx), ARGON2_OK);
  EXPECT_EQ(out, kRfcTag);
}

/* ==================================================
 * Negative Tests
 * ================================================== */

/**
 * @brief   Verify flipping one bit of a valid tag makes EVP_DecryptFinal_ex reject the message
 */
TEST(KatTest, TamperedTagFailsVerification) {
  for (const GcmVector& vec : kGcmVectors) {
    SCOPED_TRACE(testing::Message() << "gcmEncryptExtIV256.rsp " << vec.name);

    const std::vector<uint8_t> right = FromHex(vec.tag);

    ASSERT_EQ(right.size(), kTagSize);

    /* Flip each bit of each tag byte in turn */

    for (size_t i = 0; i < right.size(); i++) {
      for (int j = 0; j < 8; j++) {
        std::vector<uint8_t> wrong = right;
        std::vector<uint8_t> pt;

        wrong[i] ^= static_cast<uint8_t>(1U << j);

        EXPECT_EQ(GcmDecrypt(vec, wrong, pt), Result::kFailure);
      }
    }
  }
}
