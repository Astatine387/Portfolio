/**
 * @file    aes_gcm_fixture.h
 * @brief   Shared fixture and helpers for the AES-GCM test files
 * @author  Astatine387
 */

#pragma once

#include <gtest/gtest.h>
#include <openssl/evp.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "common/constants.h"
#include "core/aes_gcm.h"
#include "core/file_header.h"
#include "core/secure_key.h"
#include "utils/platform.h"

/**
 * @class   AesGcmTest
 * @brief   Test fixture for AesGcm tests
 */
class AesGcmTest : public ::testing::Test {
 protected:
  std::string last_error_;

  /* Fixed names in the working directory, shared by every case built on this fixture. Two cases running
   * at once would be writing over each other's files, so the suite has to run serially. */

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
   *
   * Deriving at the shipped parameters would cost half a gigabyte and four passes for every key, and
   * none of these tests is about the derivation. They still sit inside the accepted range, so a file
   * written with them is one the program would read.
   */
  static KdfParams MinParams() {
    return KdfParams{ .time_cost = kMinTimeCost, .mem_cost = kMinMemCost, .parallelism = kMinParallelism };
  }

  /**
   * @brief   Build a fixed salt
   */
  static std::array<uint8_t, kSaltSize> MakeSalt(uint8_t byte) {
    std::array<uint8_t, kSaltSize> salt{};
    salt.fill(byte);
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
   *
   * Argon2id is deliberately slow, and the suite asks for the same handful of keys over and over, so
   * the cache is the difference between a fast run and a slow one. It lives to the end of the process
   * on purpose: a key is a pure function of the password, the salt and the parameters.
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
   * @param   data    File data
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
   * @class   FilePair
   * @brief   A source and a destination stream
   */
  class FilePair {
   public:
    /**
     * @brief   Open a source for reading and a destination in the given mode
     * @param   src         Source file path
     * @param   dst         Destination file path
     * @param   dst_mode    Mode the destination file is opened with
     */
    FilePair(const std::string& src, const std::string& dst, const char* dst_mode = "wb+") {
      OpenFile(&src_, src, "rb");
      OpenFile(&dst_, dst, dst_mode);
    }

    ~FilePair() {
      if (src_ != nullptr) {
        fclose(src_);
      }

      if (dst_ != nullptr) {
        fclose(dst_);
      }
    }

    FilePair(const FilePair&) = delete;             // Delete copy constructor
    FilePair& operator=(const FilePair&) = delete;  // Delete copy assignment operator
    FilePair(FilePair&&) = delete;                  // Delete move constructor
    FilePair& operator=(FilePair&&) = delete;       // Delete move assignment operator

    [[nodiscard]] FILE* Src() const { return src_; }
    [[nodiscard]] FILE* Dst() const { return dst_; }

   private:
    FILE* src_ = nullptr;  // Source stream
    FILE* dst_ = nullptr;  // Destination stream
  };

  /* Deterministic plaintext pattern: byte i is the top byte of the 32-bit product
   * i * kPatternMixer. Both the shift and the multiplier are load-bearing, and the
   * assertions below hold a replacement of either to what the tests need.
   *
   * Why the top byte. Carries in a product only travel upward, so the low m bits of i * k
   * depend on nothing but the low m bits of i. Slicing a lower byte out therefore repeats on
   * a short cycle however good the multiplier is: byte 0 repeats every 256 indices and byte 1
   * every 65536, the latter being exactly one chunk. Only the top byte depends on every bit
   * of the index, which is what gives the pattern a period no file here can reach.
   *
   * Why this multiplier. 0x9E3779B1 is the nearest prime to 2^32 divided by the golden ratio,
   * the constant Knuth gives for multiplicative hashing. The golden ratio is the hardest
   * number to approximate by a fraction, so no bit window of the product resonates with a
   * stride, and the pattern keeps working for any chunk size in the accepted range rather
   * than for one. It must also be odd, which makes i -> i * kPatternMixer one-to-one over
   * 32 bits. Being prime is incidental.
   *
   * What breaks without them. Every chunk would carry byte-identical plaintext, and a round
   * trip could no longer tell a reordered or misplaced chunk from an intact one. Oddness
   * alone does not suffice: 2^24 + 1 is odd, yet stepping one chunk with it moves only bits
   * the shift throws away.
   */
  static constexpr uint32_t kPatternMixer = 2654435761U;
  static constexpr uint32_t kPatternShift = 24;

  static_assert(kPatternMixer % 2 == 1, "Plaintext pattern multiplier must be odd");
  static_assert(kPatternShift + 8 == 32, "Only the top byte of the product depends on every bit of the index");
  static_assert((kPatternMixer * static_cast<uint32_t>(kChunkSize) >> kPatternShift) != 0,
                "Plaintext pattern must differ between one chunk and the next");

  /**
   * @brief   Build a deterministic plaintext of a given size
   * @param   size    Number of bytes
   * @return  Buffer filled with a position-dependent pattern that does not repeat
   */
  static std::vector<uint8_t> MakePlain(size_t size) {
    std::vector<uint8_t> plain(size);

    for (size_t i = 0; i < size; i++) {
      const uint32_t mixed = static_cast<uint32_t>(i) * kPatternMixer;

      plain[i] = static_cast<uint8_t>(mixed >> kPatternShift);
    }

    return plain;
  }

  /**
   * @brief   Lowercase hexadecimal SHA-256 of a buffer
   * @param   bytes   Buffer to digest
   * @return  64-character digest string
   */
  static std::string Sha256Hex(const std::vector<uint8_t>& bytes) {
    constexpr std::string_view kDigits = "0123456789abcdef";
    constexpr size_t kDigestSize = 32;

    std::array<uint8_t, kDigestSize> md{};
    unsigned int len = 0;

    EXPECT_EQ(EVP_Digest(bytes.data(), bytes.size(), md.data(), &len, EVP_sha256(), nullptr), 1);

    std::string hex;

    for (uint8_t byte : md) {
      hex += kDigits[static_cast<size_t>(byte >> 4)];
      hex += kDigits[static_cast<size_t>(byte & 0x0F)];
    }

    return hex;
  }

  /**
   * @brief   Overwrite a file with the given bytes
   * @param   path    File path
   * @param   bytes   Content to write
   */
  void Store(const std::string& path, const std::vector<uint8_t>& bytes) {
    FILE* file = nullptr;

    OpenFile(&file, path, "wb");

    ASSERT_NE(file, nullptr);

    if (!bytes.empty()) {
      EXPECT_EQ(fwrite(bytes.data(), sizeof(uint8_t), bytes.size(), file), bytes.size());
    }

    fclose(file);
  }

  /**
   * @brief   Encrypt a buffer and return the resulting file
   * @param   plain   Plaintext to encrypt
   * @param   salt    Salt written to the header
   * @param   pw      Password the key is derived from
   * @return  Bytes of the encrypted file
   */
  std::vector<uint8_t> EncryptBytes(const std::vector<uint8_t>& plain, const std::array<uint8_t, kSaltSize>& salt,
                                    const char* pw) {
    AesGcm aes;
    std::vector<uint8_t> cipher;

    Store(src_path_, plain);

    {
      FilePair files(src_path_, enc_path_);

      EXPECT_EQ(aes.Encrypt(files.Src(), files.Dst(), MakeKey(pw, salt), salt, MinParams()), Result::kSuccess);
    }

    Read(enc_path_, cipher);

    return cipher;
  }

  /**
   * @brief   Decrypt a file
   * @param   cipher  Bytes of the encrypted file
   * @param   plain   Recovered plaintext
   * @param   salt    Salt the key is derived with
   * @param   pw      Password the key is derived from
   * @return  Outcome reported by the engine
   */
  Result DecryptBytes(const std::vector<uint8_t>& cipher, std::vector<uint8_t>& plain,
                      const std::array<uint8_t, kSaltSize>& salt, const char* pw) {
    AesGcm aes;

    Store(enc_path_, cipher);
    RemoveFile(dec_path_);

    last_error_.clear();

    aes.SetErrorCallback([this](const char* msg) { last_error_ += msg; });

    Result res = Result::kFailure;

    {
      FilePair files(enc_path_, dec_path_);

      res = aes.Decrypt(files.Src(), files.Dst(), MakeKey(pw, salt));
    }

    plain.clear();

    if (res == Result::kSuccess) {
      Read(dec_path_, plain);
    }

    return res;
  }

  /**
   * @brief   Offset of one chunk inside an encrypted file
   * @param   index   Chunk index, starting at zero
   * @return  Byte offset of the chunk's first ciphertext byte
   */
  static size_t ChunkAt(size_t index) { return kHeaderSize + index * (kChunkSize + kTagSize); }

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
