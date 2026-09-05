/**
 * @file    aes_gcm_format_test.cpp
 * @brief   On-disk format produced by the AES-GCM engine
 * @author  Astatine387
 */

#include <gtest/gtest.h>
#include <openssl/evp.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <string_view>
#include <vector>

#include "core/file_header.h"
#include "tests/aes_gcm_fixture.h"
#include "utils/byte_order.h"

/**
 * @class   AesGcmFormatTest
 * @brief   Fixture for the tests that pin the bytes an encrypted file is made of
 */
class AesGcmFormatTest : public AesGcmTest {};

/* ==================================================
 * Framing Tests
 * ================================================== */

/**
 * @brief   Verify every chunk boundary round-trips and produces the documented file size
 */
TEST_F(AesGcmFormatTest, FramingRoundTripsAcrossChunkBoundaries) {
  const std::array<size_t, 9> sizes{ 0,
                                     1,
                                     kChunkSize - 1,
                                     kChunkSize,
                                     kChunkSize + 1,
                                     2 * kChunkSize - 1,
                                     2 * kChunkSize,
                                     2 * kChunkSize + 1,
                                     5 * kChunkSize + 123 };
  const auto salt = MakeSalt(0xA5);

  for (size_t size : sizes) {
    SCOPED_TRACE(testing::Message() << "plaintext=" << size);

    const std::vector<uint8_t> plain = MakePlain(size);
    const std::vector<uint8_t> cipher = EncryptBytes(plain, salt, "password");
    const size_t chunks = size == 0 ? 1 : (size + kChunkSize - 1) / kChunkSize;

    EXPECT_EQ(cipher.size(), kHeaderSize + size + chunks * kTagSize);

    std::vector<uint8_t> copy;

    EXPECT_EQ(DecryptBytes(cipher, copy, salt, "password"), Result::kSuccess);
    EXPECT_EQ(copy, plain);
  }
}

/* ==================================================
 * Golden Vector Test
 * ================================================== */

/**
 * @brief   Verify a fixed input still produces the byte-identical file it produced before
 *
 * Where kGoldenDigest comes from: this implementation produced it. No specification, reference
 * tool or third party stands behind the value. It was pinned by writing the test with a
 * placeholder digest, running it once, and recording the value the failure reported. That makes
 * it a regression pin, which is a weaker thing than the known-answer vectors in kat_test.cpp,
 * and it has to be read as such.
 *
 * What it proves: the format has not drifted. The header layout, the chunk framing, the nonce
 * derivation and the associated data all feed into these bytes, so altering any of them fails
 * this test at once.
 *
 * What it does not prove: that the cryptography is right. An implementation that was wrong when
 * the value was recorded would agree with itself forever. Correctness rests on the NIST CAVP and
 * RFC 9106 vectors in kat_test.cpp, and on the framing and associated data tests beside this one.
 *
 * When regenerating the value is legitimate: only alongside a deliberate change to the format or
 * to the inputs below. A deliberate format change also means a new magic number, because this
 * format carries no version field. A failure nobody intended is a regression, and re-pinning the
 * digest to make it pass would throw away the only thing this test does.
 *
 * How to check the value without trusting this test: encrypt MakePlain(2 * kChunkSize + 1000)
 * under the password "golden-password", a salt of sixteen 0x42 bytes and MinParams(), then run
 * sha256sum over the resulting file. Going outside also rules out the case where Sha256Hex is
 * broken and merely agrees with a digest that was recorded from the same broken helper.
 */
TEST_F(AesGcmFormatTest, GoldenVectorIsStable) {
  constexpr std::string_view kGoldenDigest = "428dccccae22d0b6aaa6ccb45df1292e2487ccce754382d79b900e8b9572e107";
  constexpr size_t kGoldenPlainSize = 2 * kChunkSize + 1000;

  const auto salt = MakeSalt(0x42);
  const std::vector<uint8_t> cipher = EncryptBytes(MakePlain(kGoldenPlainSize), salt, "golden-password");

  ASSERT_EQ(cipher.size(), kHeaderSize + kGoldenPlainSize + 3 * kTagSize);

  const std::array<uint8_t, kHeaderSize> expected_header{
    0xE0, 0x7B, 0xCA, 0x75,                          // Magic
    0x10,                                            // ChunkSizeLog2 = 16
    0x01, 0x00, 0x00, 0x00,                          // TimeCost = 1, little-endian
    0x00, 0x00, 0x01, 0x00,                          // MemCost = 65536, little-endian
    0x01, 0x00, 0x00, 0x00,                          // Parallelism = 1, little-endian
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,  // Salt
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
  };

  EXPECT_EQ(memcmp(cipher.data(), expected_header.data(), kHeaderSize), 0);
  EXPECT_EQ(Sha256Hex(cipher), kGoldenDigest);
}

/* ==================================================
 * Context Reuse Test
 * ================================================== */

/**
 * @brief   Verify re-initializing only the nonce matches a context built from scratch
 */
TEST_F(AesGcmFormatTest, SharedContextMatchesFreshContext) {
  constexpr size_t kChunks = 3;
  constexpr size_t kLen = 512;
  const auto salt = MakeSalt(0xA5);
  const SecureKey& key = MakeKey("password", salt);
  FileHeader header;

  header.chunk_log2 = kChunkSizeLog2;
  header.params = MinParams();
  header.salt = salt;

  std::array<uint8_t, kHeaderSize> aad{};

  SerializeHeader(aad, header);

  const std::vector<uint8_t> plain = MakePlain(kLen);
  std::vector<std::vector<uint8_t>> shared(kChunks);

  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

  ASSERT_NE(ctx, nullptr);

  ASSERT_EQ(EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr), 1);
  ASSERT_EQ(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(kNonceSize), nullptr), 1);
  ASSERT_EQ(EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.Bytes().data(), nullptr), 1);

  for (size_t i = 0; i < kChunks; i++) {
    std::array<uint8_t, kNonceSize> nonce{};

    StoreBE64(nonce.data() + kNonceSize - 1 - sizeof(uint64_t), i);

    nonce[kNonceSize - 1] = i + 1 == kChunks ? 0x01 : 0x00;

    shared[i].assign(kLen + kTagSize, 0);

    int outlen = 0;

    ASSERT_EQ(EVP_EncryptInit_ex(ctx, nullptr, nullptr, nullptr, nonce.data()), 1);
    ASSERT_EQ(EVP_EncryptUpdate(ctx, nullptr, &outlen, aad.data(), static_cast<int>(aad.size())), 1);
    ASSERT_EQ(EVP_EncryptUpdate(ctx, shared[i].data(), &outlen, plain.data(), static_cast<int>(kLen)), 1);

    std::array<uint8_t, kBlockSize> final_block{};

    ASSERT_EQ(EVP_EncryptFinal_ex(ctx, final_block.data(), &outlen), 1);
    ASSERT_EQ(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, static_cast<int>(kTagSize), shared[i].data() + kLen), 1);
  }

  EVP_CIPHER_CTX_free(ctx);

  for (size_t i = 0; i < kChunks; i++) {
    SCOPED_TRACE(testing::Message() << "chunk=" << i);

    std::array<uint8_t, kNonceSize> nonce{};

    StoreBE64(nonce.data() + kNonceSize - 1 - sizeof(uint64_t), i);

    nonce[kNonceSize - 1] = i + 1 == kChunks ? 0x01 : 0x00;

    std::vector<uint8_t> fresh(kLen + kTagSize, 0);

    EVP_CIPHER_CTX* one = EVP_CIPHER_CTX_new();

    ASSERT_NE(one, nullptr);

    int outlen = 0;

    ASSERT_EQ(EVP_EncryptInit_ex(one, EVP_aes_256_gcm(), nullptr, nullptr, nullptr), 1);
    ASSERT_EQ(EVP_CIPHER_CTX_ctrl(one, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(kNonceSize), nullptr), 1);
    ASSERT_EQ(EVP_EncryptInit_ex(one, nullptr, nullptr, key.Bytes().data(), nonce.data()), 1);
    ASSERT_EQ(EVP_EncryptUpdate(one, nullptr, &outlen, aad.data(), static_cast<int>(aad.size())), 1);
    ASSERT_EQ(EVP_EncryptUpdate(one, fresh.data(), &outlen, plain.data(), static_cast<int>(kLen)), 1);

    std::array<uint8_t, kBlockSize> final_block{};

    ASSERT_EQ(EVP_EncryptFinal_ex(one, final_block.data(), &outlen), 1);
    ASSERT_EQ(EVP_CIPHER_CTX_ctrl(one, EVP_CTRL_GCM_GET_TAG, static_cast<int>(kTagSize), fresh.data() + kLen), 1);

    EVP_CIPHER_CTX_free(one);

    EXPECT_EQ(fresh, shared[i]);
  }
}

/* ==================================================
 * Associated Data Test
 * ================================================== */

/**
 * @brief   Verify the header is authenticated, by patching a field that changes nothing else
 */
TEST_F(AesGcmFormatTest, HeaderIsAuthenticatedAsAssociatedData) {
  /* Smaller than the smallest chunk size the format allows, so the file stays a single chunk
   * for every value byte 4 is patched to. Tying this to kChunkSize instead would break the
   * test: under a patched chunk_log2 of 12 the file would span sixteen chunks and be refused
   * for a framing mismatch rather than for the associated data. */

  constexpr size_t kUnderAnyChunkSize = (size_t{ 1 } << kMinChunkSizeLog2) - 1;

  const auto salt = MakeSalt(0xA5);
  const std::vector<uint8_t> plain = MakePlain(kUnderAnyChunkSize);
  const std::vector<uint8_t> cipher = EncryptBytes(plain, salt, "password");

  ASSERT_EQ(cipher.size(), kHeaderSize + plain.size() + kTagSize);
  ASSERT_EQ(cipher[4], kChunkSizeLog2);

  for (uint8_t log2 = kMinChunkSizeLog2; log2 <= kMaxChunkSizeLog2; log2++) {
    if (log2 == kChunkSizeLog2) {
      continue;
    }

    SCOPED_TRACE(testing::Message() << "chunk_log2 patched to " << static_cast<int>(log2));

    std::vector<uint8_t> patched = cipher;

    patched[4] = log2;

    std::vector<uint8_t> copy;

    EXPECT_EQ(DecryptBytes(patched, copy, salt, "password"), Result::kFailure);
    EXPECT_TRUE(copy.empty());
  }
}
