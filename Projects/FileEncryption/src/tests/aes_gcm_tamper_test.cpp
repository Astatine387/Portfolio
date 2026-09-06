/**
 * @file    aes_gcm_tamper_test.cpp
 * @brief   Rejection of every way an encrypted file can be altered
 * @author  Astatine387
 */

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <string>
#include <vector>

#include "tests/aes_gcm_fixture.h"

/* ==================================================
 * Tamper Matrix Tests
 * ================================================== */

/**
 * @class   AesGcmTamperTest
 * @brief   Fixture holding one valid two-chunk file that each case mutates
 */
class AesGcmTamperTest : public AesGcmTest {
 protected:
  std::array<uint8_t, kSaltSize> salt_ = MakeSalt(0xA5);
  std::vector<uint8_t> plain_;
  std::vector<uint8_t> cipher_;

  /* Three is the smallest count that gives a first, a middle and a last chunk at once, so the swap case
   * has two interior chunks to exchange and truncation has a final chunk to remove that is not also the
   * first. Exactly full matters as much: with a short tail, a cut at a chunk boundary would change the
   * framing as well as the flag, and the two reasons for the rejection could no longer be told apart. */

  static constexpr size_t kChunks = 3;

  /**
   * @brief   Build a three-chunk file whose final chunk is exactly full
   */
  void SetUp() override {
    plain_ = MakePlain(kChunks * kChunkSize);
    cipher_ = EncryptBytes(plain_, salt_, "password");

    ASSERT_EQ(cipher_.size(), kHeaderSize + kChunks * (kChunkSize + kTagSize));
  }

  /**
   * @brief   Assert a mutated file is refused and leaves no plaintext behind
   * @param   msg     Description of the mutation
   * @param   bytes   Mutated file image
   */
  void ExpectRejected(const std::string& msg, const std::vector<uint8_t>& bytes) {
    SCOPED_TRACE(testing::Message() << msg);

    std::vector<uint8_t> copy;

    EXPECT_EQ(DecryptBytes(bytes, copy, salt_, "password"), Result::kFailure);
    EXPECT_TRUE(copy.empty());
  }

  /**
   * @brief   Assert flipping the low bit of one byte is refused
   * @param   msg     Description of the field
   * @param   offset  Byte to flip
   */
  void ExpectFlipRejected(const std::string& msg, size_t offset) {
    std::vector<uint8_t> bytes = cipher_;

    bytes[offset] ^= 0x01;

    ExpectRejected(msg + " at offset " + std::to_string(offset), bytes);
  }
};

/**
 * @brief   Verify the file every other case mutates decrypts cleanly when left alone
 */
TEST_F(AesGcmTamperTest, AcceptsTheUntamperedFile) {
  std::vector<uint8_t> copy;

  EXPECT_EQ(DecryptBytes(cipher_, copy, salt_, "password"), Result::kSuccess);
  EXPECT_EQ(copy, plain_);
}

/**
 * @brief   Verify a bit flip in the header is refused
 */
TEST_F(AesGcmTamperTest, RejectsHeaderBitFlips) {
  ExpectFlipRejected("magic", 0);
  ExpectFlipRejected("magic", 3);
  ExpectFlipRejected("chunk_log2", 4);
  ExpectFlipRejected("time cost", 5);
  ExpectFlipRejected("memory cost", 9);
  ExpectFlipRejected("parallelism", 13);
  ExpectFlipRejected("salt", 17);
  ExpectFlipRejected("salt", kHeaderSize - 1);
}

/**
 * @brief   Verify a bit flip in any chunk's ciphertext is refused
 */
TEST_F(AesGcmTamperTest, RejectsCiphertextBitFlips) {
  for (size_t chunk = 0; chunk < kChunks; chunk++) {
    ExpectFlipRejected("ciphertext of chunk " + std::to_string(chunk), ChunkAt(chunk));
    ExpectFlipRejected("ciphertext of chunk " + std::to_string(chunk), ChunkAt(chunk) + kChunkSize - 1);
  }
}

/**
 * @brief   Verify a bit flip in any chunk's tag is refused
 */
TEST_F(AesGcmTamperTest, RejectsTagBitFlips) {
  for (size_t chunk = 0; chunk < kChunks; chunk++) {
    ExpectFlipRejected("tag of chunk " + std::to_string(chunk), ChunkAt(chunk) + kChunkSize);
    ExpectFlipRejected("tag of chunk " + std::to_string(chunk), ChunkAt(chunk) + kChunkSize + kTagSize - 1);
  }
}

/**
 * @brief   Verify reordering two chunks is refused, because the counter is part of the nonce
 */
TEST_F(AesGcmTamperTest, RejectsSwappedChunks) {
  constexpr size_t kBlock = kChunkSize + kTagSize;

  std::vector<uint8_t> bytes = cipher_;

  std::swap_ranges(bytes.begin() + static_cast<ptrdiff_t>(ChunkAt(0)),
                   bytes.begin() + static_cast<ptrdiff_t>(ChunkAt(0) + kBlock),
                   bytes.begin() + static_cast<ptrdiff_t>(ChunkAt(1)));

  ExpectRejected("two non-final chunks swapped", bytes);
}

/**
 * @brief   Verify dropping the final chunk is refused, because the flag byte moves
 */
TEST_F(AesGcmTamperTest, RejectsTruncationToWholeChunk) {
  std::vector<uint8_t> bytes = cipher_;

  bytes.resize(ChunkAt(kChunks - 1));

  ExpectRejected("final chunk removed", bytes);
}

/**
 * @brief   Verify a cut inside a chunk is refused rather than underflowing the length
 */
TEST_F(AesGcmTamperTest, RejectsTruncationInsideChunk) {
  /* Leave a tail too short to hold a tag */

  for (size_t tail = 1; tail < kTagSize; tail++) {
    std::vector<uint8_t> bytes = cipher_;

    bytes.resize(ChunkAt(kChunks - 1) + tail);

    ExpectRejected("truncated to a " + std::to_string(tail) + " byte tail", bytes);

    EXPECT_NE(last_error_.find("truncated or corrupted"), std::string::npos);
  }
}

/**
 * @brief   Verify appending a chunk that is valid on its own is refused
 */
TEST_F(AesGcmTamperTest, RejectsAppendedChunk) {
  std::vector<uint8_t> bytes = cipher_;

  bytes.insert(bytes.end(), cipher_.begin() + static_cast<ptrdiff_t>(ChunkAt(0)),
               cipher_.begin() + static_cast<ptrdiff_t>(ChunkAt(0) + kChunkSize + kTagSize));

  ExpectRejected("extra valid-looking chunk appended", bytes);
}

/**
 * @brief   Verify a data region too short to hold a tag is refused
 */
TEST_F(AesGcmTamperTest, RejectsShortDataRegion) {
  for (size_t region = 1; region < kTagSize; region++) {
    std::vector<uint8_t> bytes = cipher_;

    bytes.resize(kHeaderSize + region);

    ExpectRejected("data region of " + std::to_string(region) + " bytes", bytes);

    EXPECT_NE(last_error_.find("too small"), std::string::npos);
  }
}

/**
 * @brief   Verify a chunk taken from another file under the same password is refused
 */
TEST_F(AesGcmTamperTest, RejectsChunkFromAnotherFile) {
  const auto other_salt = MakeSalt(0x5A);
  const std::vector<uint8_t> other = EncryptBytes(MakePlain(kChunks * kChunkSize), other_salt, "password");

  /* Same length, so the splice below replaces a chunk rather than resizing the file. Without it a
   * rejection could be down to the framing no longer adding up, which is a different test. */

  ASSERT_EQ(other.size(), cipher_.size());

  std::vector<uint8_t> bytes = cipher_;

  std::copy_n(other.begin() + static_cast<ptrdiff_t>(ChunkAt(0)), kChunkSize + kTagSize,
              bytes.begin() + static_cast<ptrdiff_t>(ChunkAt(0)));

  ExpectRejected("chunk spliced from another file", bytes);
}

/* ==================================================
 * Write Ordering Tests
 * ================================================== */

/**
 * @class   AesGcmWriteOrderTest
 * @brief   Fixture for the tests that watch what reaches the disk before a failure
 */
class AesGcmWriteOrderTest : public AesGcmTest {};

/**
 * @brief   Verify nothing past the last good chunk reaches the disk when a chunk fails
 */
TEST_F(AesGcmWriteOrderTest, StopsWritingAtTheFirstBadChunk) {
  constexpr size_t kChunks = 5;
  constexpr size_t kBad = 3;
  const auto salt = MakeSalt(0xA5);
  const std::vector<uint8_t> plain = MakePlain(kChunks * kChunkSize);

  std::vector<uint8_t> cipher = EncryptBytes(plain, salt, "password");

  ASSERT_EQ(cipher.size(), kHeaderSize + kChunks * (kChunkSize + kTagSize));

  cipher[ChunkAt(kBad) + 10] ^= 0x01;

  AesGcm aes;

  Store(enc_path_, cipher);
  RemoveFile(dec_path_);

  {
    FilePair files(enc_path_, dec_path_);

    EXPECT_EQ(aes.Decrypt(files.Src(), files.Dst(), MakeKey("password", salt)), Result::kFailure);
  }

  /* Chunks 0 to 2 were authenticated before they were written, and nothing beyond them was */

  std::vector<uint8_t> written;

  Read(dec_path_, written);

  EXPECT_EQ(written.size(), kBad * kChunkSize);
  EXPECT_EQ(written, std::vector<uint8_t>(plain.begin(), plain.begin() + static_cast<ptrdiff_t>(written.size())));
}
