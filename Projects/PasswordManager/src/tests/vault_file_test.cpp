/**
 * @file    vault_file_test.cpp
 * @brief   Unit tests for Vault file management functions
 * @author  Astatine387
 */

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <vector>

#ifndef _WIN32
#include <sys/stat.h>
#endif

#include "core/secure_key.h"
#include "core/vault.h"
#include "core/vault_header.h"
#include "utils/byte_order.h"
#include "utils/platform.h"

namespace {

/* Header field offsets, restated here rather than imported from the module under test, so that moving a field in the
 * format has to be done twice before these tests agree that it moved */

constexpr size_t kVersionOff = 4;
constexpr size_t kTimeCostOff = 5;
constexpr size_t kMemCostOff = 9;
constexpr size_t kParallelismOff = 13;
constexpr size_t kSaltOff = 17;
constexpr size_t kCommitOff = 33;

static_assert(kVersionOff == kMagicSize, "Version does not follow the magic number");
static_assert(kTimeCostOff == kVersionOff + kVersionSize, "Time cost does not follow the version");
static_assert(kMemCostOff == kTimeCostOff + sizeof(uint32_t), "Memory cost does not follow the time cost");
static_assert(kParallelismOff == kMemCostOff + sizeof(uint32_t), "Parallelism does not follow the memory cost");
static_assert(kSaltOff == kParallelismOff + sizeof(uint32_t), "Salt does not follow the parameters");
static_assert(kCommitOff == kSaltOff + kSaltSize, "Commitment does not follow the salt");
static_assert(kCommitOff + kCommitSize == kHeaderSize, "Header field offsets do not fill the header");

/**
 * @brief   Which check refuses a vault whose header has had one byte flipped
 * @param   off     Byte offset within the header
 * @return  Substring the reported error is expected to contain
 *
 * The mapping is the point of the sweep. That every offset fails says little on its own; which mechanism catches
 * each one is a property of this exact layout and of the parameters the swept vault is written with, and writing it
 * down is what makes the sweep documentation rather than a smoke test.
 *
 *  0..3    magic        kMagicNum differs from kLegacyMagicNum in all four bytes, so one flipped byte can reach
 *                       neither value -> kBadMagic
 *  4       version      Anything but kFormatVersion -> kBadVersion
 *  5..8    time_cost    kMinTimeCost flips to 254 or higher, all far outside the range -> kBadParams
 *  9..10   mem_cost     The two low bytes of kMinMemCost flip to values still inside the range, so these two are the
 *                       only header bytes that get past validation while changing the derivation -> commitment
 *  11..12  mem_cost     The two high bytes flip to gigabytes -> kBadParams
 *  13..16  parallelism  kMinParallelism flips as time_cost does -> kBadParams
 *  17..32  salt         A different salt derives a different key, and with it a different commitment -> commitment
 *  33..64  commitment   Compared against the derivation directly -> commitment
 *
 * No offset reaches the authentication tag. Whatever survives the range checks changes either the key or the stored
 * commitment, and the commitment is compared before anything is decrypted, so a header edit is refused without a
 * ciphertext byte being read. The associated data covers these bytes too, and it is AesGcmTest.MismatchedAad that
 * shows that wiring works: here the commitment always answers first.
 */
const char* ExpectedMessage(size_t off) {
  if (off < kVersionOff) {
    return "Not a vault file";
  }

  if (off < kTimeCostOff) {
    return "Unsupported vault format version";
  }

  if (off < kSaltOff && off != kMemCostOff && off != kMemCostOff + 1) {
    return "Unsupported key derivation parameters";
  }

  return "Incorrect master password";
}

}  // namespace

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
   * @brief   Write a vault file holding the given image, derived under the given salt and parameters
   * @param   path    File path
   * @param   img     Plaintext vault image
   * @param   salt    Salt to derive with and record in the header
   * @param   params  Argon2id parameters to derive with and record in the header
   *
   * Assembled the way SaveVaultWith assembles one, commitment and associated data included, so a crafted vault
   * differs from a real one only in what its image says.
   */
  static void WriteVault(const std::string& path, std::vector<uint8_t>& img, const std::array<uint8_t, kSaltSize>& salt,
                         const KdfParams& params = {}) {
    SecureKey key = KeyForFile(salt, params);

    VaultHeader header;

    header.params = key.Params();

    std::ranges::copy(key.Salt(), header.salt.begin());
    std::ranges::copy(key.Commitment(), header.commitment.begin());

    std::vector<uint8_t> buff(kHeaderSize + kIVSize + img.size() + kTagSize);

    SerializeHeader(std::span<uint8_t, kHeaderSize>(buff.data(), kHeaderSize), header);

    AesGcm aes;

    EXPECT_EQ(aes.Encrypt(img.data(), buff.data() + kHeaderSize, img.size(), key, std::span(buff.data(), kHeaderSize)),
              Result::kSuccess);

    WriteFile(path, buff);
  }

  /**
   * @brief   Read the Argon2id parameters out of a vault file header
   * @param   buff    Vault file contents
   * @return  Parameters as stored in the header
   */
  static KdfParams ReadHeaderParams(const std::vector<uint8_t>& buff) {
    KdfParams params{};

    EXPECT_GE(buff.size(), kHeaderSize);

    params.time_cost = LoadLE32(buff.data() + kTimeCostOff);
    params.mem_cost = LoadLE32(buff.data() + kMemCostOff);
    params.parallelism = LoadLE32(buff.data() + kParallelismOff);

    return params;
  }

  /**
   * @brief   Replace the Argon2id parameters in the vault file, leaving the body untouched
   * @param   params  Parameters to store
   */
  void PatchHeaderParams(const KdfParams& params) {
    std::vector<uint8_t> buff = ReadFile(path_);

    ASSERT_GE(buff.size(), kHeaderSize);

    StoreLE32(buff.data() + kTimeCostOff, params.time_cost);
    StoreLE32(buff.data() + kMemCostOff, params.mem_cost);
    StoreLE32(buff.data() + kParallelismOff, params.parallelism);

    WriteFile(path_, buff);
  }

  /**
   * @brief   Replace the vault file with an empty vault built under the given parameters
   * @param   params  Argon2id parameters to derive with and record
   */
  void MakeVaultWith(const KdfParams& params) {
    std::vector<uint8_t> img(kCountSize);

    StoreLE32(img.data(), 0);

    std::array<uint8_t, kSaltSize> salt{};
    salt.fill(0x33);

    WriteVault(path_, img, salt, params);
  }
};

/**
 * @class   VaultHeaderTamperTest
 * @brief   Fixture flipping one header byte per case, over the whole header
 */
class VaultHeaderTamperTest : public VaultFileTest, public testing::WithParamInterface<size_t> {
 protected:
  /**
   * @brief   Replace the base fixture's vault with one written at the cheapest legal parameters
   *
   * The base fixture derives at the build defaults, which is 512 MiB of Argon2id per case and more than a sweep of
   * this length needs. Those parameters are also what the offset-to-mechanism mapping above is stated against.
   */
  void SetUp() override { MakeVaultWith(MinParams()); }
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

  std::vector<uint8_t> src(kCountSize);

  StoreLE32(src.data(), 10);

  /* Write a vault the fixture password opens, so the entry count is what fails and not the password */

  std::array<uint8_t, kSaltSize> salt{};
  salt.fill(0x11);

  WriteVault(path_, src, salt);

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

  ASSERT_EQ(entry.Serialize(std::span(src).subspan(cur), epw_span), entry_size);

  /* Write a vault the fixture password opens, so the entry data is what fails and not the password */

  std::array<uint8_t, kSaltSize> salt{};
  salt.fill(0x22);

  WriteVault(path_, src, salt);

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

  /* Flip the first ciphertext byte, leaving the header and the IV intact */

  const size_t offset = kHeaderSize + kIVSize;

  ASSERT_LT(offset, fsize);

  buff[offset] ^= 0xFF;

  EXPECT_EQ(LoadLE32(buff.data()), kMagicNum);

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
 * @brief   Verify a vault written before the key commitment existed is refused, and said to be old rather than
 *          foreign
 */
TEST_F(VaultFileTest, OpenLegacyFormatFails) {
  std::vector<uint8_t> buff = ReadFile(path_);

  ASSERT_GE(buff.size(), static_cast<size_t>(kMinSize));

  StoreLE32(buff.data(), kLegacyMagicNum);

  WriteFile(path_, buff);

  EXPECT_EQ(Reload(), Result::kFailure);
  EXPECT_NE(vault_.GetLastError().find("predates the current format"), std::string::npos);
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
 * @brief   Verify a vault edited many times over saves and reopens with every password intact
 *
 * Every create, update and delete rewrites the whole image and recomputes every offset in it, so an offset written
 * against the wrong buffer, or onto the wrong entry, does not announce itself: the site and the account still read
 * correctly and the password comes back as whichever bytes that offset now lands on. A single edit moves too little
 * to show it. This one runs enough edits, over fields of deliberately unequal length, that the surviving entries end
 * up at different offsets and in a different order than they were created at, then reads every field back off the
 * disk.
 */
TEST_F(VaultFileTest, SaveAfterManyEdits) {
  /**
   * @struct  Record
   * @brief   What one entry is expected to hold, kept in step with the edits below
   */
  struct Record {
    std::string site;
    std::string acc;
    std::string pw;
  };

  std::vector<Record> records;

  /* Lengths that vary in opposite directions, so no two entries are interchangeable in size */

  for (int i = 0; i < 10; i++) {
    const size_t n = static_cast<size_t>(i);

    records.push_back({ .site = "site" + std::to_string(i) + std::string(n, 's'),
                        .acc = "acc" + std::to_string(i) + std::string(9 - n, 'a') + "@example.com",
                        .pw = "pw" + std::to_string(i) + std::string(n * 4, 'p') });
  }

  for (const auto& rec : records) {
    ASSERT_EQ(vault_.CreateEntry(rec.site, rec.acc, MakePW(rec.pw.c_str())), Result::kSuccess);
  }

  ASSERT_EQ(vault_.GetEntryCount(), 10);

  /* Three updates: one moves the entry in the ordering, one only rewrites the password, one does both. Each reads
   * the target out of the record before overwriting it, so the edit and the expectation cannot drift apart. */

  const Record moved_last = records[1];

  records[1].site = "zzz-moved-last";

  ASSERT_EQ(vault_.UpdateEntry(moved_last.site, moved_last.acc, records[1].site, records[1].acc,
                               MakePW(records[1].pw.c_str())),
            UpdateResult::kSuccess);

  const Record repassworded = records[4];

  records[4].pw = "rewritten-" + std::string(37, 'r');

  ASSERT_EQ(vault_.UpdateEntry(repassworded.site, repassworded.acc, records[4].site, records[4].acc,
                               MakePW(records[4].pw.c_str())),
            UpdateResult::kSuccess);

  const Record moved_first = records[7];

  records[7].site = "aaa-moved-first";
  records[7].pw = "short";

  ASSERT_EQ(vault_.UpdateEntry(moved_first.site, moved_first.acc, records[7].site, records[7].acc,
                               MakePW(records[7].pw.c_str())),
            UpdateResult::kSuccess);

  /* Two deletes, one from either end of the ordering */

  ASSERT_EQ(vault_.DeleteEntry(records[0].site, records[0].acc), Result::kSuccess);
  ASSERT_EQ(vault_.DeleteEntry(records[8].site, records[8].acc), Result::kSuccess);

  records.erase(records.begin() + 8);
  records.erase(records.begin());

  ASSERT_EQ(vault_.GetEntryCount(), 8);

  /* Correct in memory before the save, so a failure below tells the two apart */

  for (const auto& rec : records) {
    Password got;

    ASSERT_TRUE(vault_.GetEntryPW(rec.site, rec.acc, got)) << rec.site;
    EXPECT_TRUE(got.Equal(MakePW(rec.pw.c_str()))) << rec.site;
  }

  ASSERT_EQ(vault_.SaveVault(path_), Result::kSuccess);
  ASSERT_EQ(Reload(), Result::kSuccess);

  EXPECT_EQ(vault_.GetEntryCount(), 8);

  const auto& entries = vault_.GetEntries();

  for (const auto& rec : records) {
    EXPECT_NE(entries.find({ .site = rec.site, .acc = rec.acc }), entries.end()) << rec.site;

    Password got;

    ASSERT_TRUE(vault_.GetEntryPW(rec.site, rec.acc, got)) << rec.site;
    EXPECT_TRUE(got.Equal(MakePW(rec.pw.c_str()))) << rec.site;
  }
}

/**
 * @brief   Verify every vault this build writes is one it can reopen with every field intact
 *
 * The property whose absence let the entry-size invariant break. The suite covers each class thoroughly on its own,
 * but nothing asserted that what the CRUD layer accepts is what the file layer takes back, and the two halves drifted
 * apart in exactly that gap: an entry a byte under kMinEntrySize was accepted, serialized, encrypted and written
 * perfectly well, then refused on the way back in. Nothing was wrong with any one class.
 *
 * The cases are the edges of what the format accepts, since an off-by-one between the write path and the read path
 * shows up there and nowhere else. Multi-byte UTF-8 is carried because the ceilings are byte counts while the dialog
 * counts characters, so 128 two-byte or 64 four-byte characters is what lands on exactly 256 bytes without looking
 * like it.
 */
TEST_F(VaultFileTest, EveryVaultCanBeReopened) {
  /**
   * @struct  Record
   * @brief   One entry, as it goes in and as it has to come back
   */
  struct Record {
    std::string site;
    std::string acc;
    std::string pw;
  };

  const std::string one_site = "s";
  const std::string one_acc = "a";
  const std::string one_pw = "p";

  const std::string max_site(static_cast<size_t>(kMaxSiteLen), 's');
  const std::string max_acc(static_cast<size_t>(kMaxAccLen), 'a');
  const std::string max_pw(static_cast<size_t>(kMaxEntryPwLen), 'p');

  /* Written as bytes rather than as characters, so that these are 256 bytes whatever the compiler's execution
   * character set is, and so the count is checkable by reading it */

  std::string utf8_site;
  std::string utf8_acc;

  for (int i = 0; i < kMaxSiteLen / 2; i++) {
    utf8_site += "\xc3\xa9";  // U+00E9, two bytes
  }

  for (int i = 0; i < kMaxAccLen / 4; i++) {
    utf8_acc += "\xf0\x9f\x94\x90";  // U+1F510, four bytes
  }

  ASSERT_EQ(utf8_site.size(), static_cast<size_t>(kMaxSiteLen));
  ASSERT_EQ(utf8_acc.size(), static_cast<size_t>(kMaxAccLen));

  const std::vector<std::vector<Record>> cases = {
    /* Zero entries */

    {},

    /* One entry, every field exactly one byte: the smallest vault that holds anything, and the one the entry-count
       check refused while the validator still accepted an empty password */

    { { .site = one_site, .acc = one_acc, .pw = one_pw } },

    /* One entry, every field exactly at its ceiling */

    { { .site = max_site, .acc = max_acc, .pw = max_pw } },

    /* Several entries mixing both extremes, so no two are interchangeable in size and a misplaced offset lands on a
       neighbour of a different length */

    { { .site = one_site, .acc = one_acc, .pw = max_pw },
      { .site = "b", .acc = max_acc, .pw = one_pw },
      { .site = max_site, .acc = "c", .pw = one_pw },
      { .site = "d", .acc = "e", .pw = max_pw } },

    /* A site and an account of multi-byte UTF-8 landing on exactly the ceiling */

    { { .site = utf8_site, .acc = utf8_acc, .pw = one_pw } },

    /* A password at either end of its range */

    { { .site = "one-byte-pw", .acc = one_acc, .pw = one_pw },
      { .site = "max-byte-pw", .acc = one_acc, .pw = max_pw } },
  };

  for (size_t i = 0; i < cases.size(); i++) {
    const std::vector<Record>& records = cases[i];

    SCOPED_TRACE(testing::Message() << "case=" << i << " entries=" << records.size());

    /* A fresh vault per case, so each one is written and read on its own rather than on what the last case left */

    ASSERT_EQ(vault_.NewVault(path_, MakePW("password")), Result::kSuccess);

    for (const auto& rec : records) {
      ASSERT_EQ(vault_.CreateEntry(rec.site, rec.acc, MakePW(rec.pw.c_str())), Result::kSuccess)
          << vault_.GetLastError();
    }

    ASSERT_EQ(vault_.SaveVault(path_), Result::kSuccess) << vault_.GetLastError();
    ASSERT_EQ(Reload(), Result::kSuccess) << vault_.GetLastError();

    EXPECT_EQ(vault_.GetEntryCount(), static_cast<int>(records.size()));

    const auto& entries = vault_.GetEntries();

    for (const auto& rec : records) {
      EXPECT_NE(entries.find({ .site = rec.site, .acc = rec.acc }), entries.end());

      /* Read back through GetEntryPW, as a caller would, so a stale offset comes back as the wrong bytes rather than
         being stepped over */

      Password got;

      ASSERT_TRUE(vault_.GetEntryPW(rec.site, rec.acc, got));
      EXPECT_TRUE(got.Equal(MakePW(rec.pw.c_str())));
    }
  }
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
  ASSERT_GT(first.size(), kHeaderSize + kIVSize + kTagSize);

  const size_t salt_off = kSaltOff;
  const size_t iv_off = kHeaderSize;
  const size_t ct_off = kHeaderSize + kIVSize;

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

#ifndef _WIN32

/**
 * @brief   Verify a save never widens the permissions of the vault it replaces
 *
 * SaveVault publishes its work by renaming a temporary over the vault, so the mode that temporary carries becomes
 * the mode of the vault. That temporary used to be chmodded to match the file it was about to replace, which meant
 * a vault left readable by everybody once stayed that way through every save afterwards, and carried setuid,
 * setgid and sticky across with it. This is the layer the defect was actually felt at, so the guarantee is pinned
 * here as well as at OpenTempFile. Only the bits that must never appear are asserted, because the umask in force
 * is free to clear owner bits too and an exact 0600 would fail on a developer who sets one.
 */
TEST_F(VaultFileTest, SaveDoesNotWidenVaultPermissions) {
  ASSERT_EQ(chmod(path_.c_str(), 0666), 0);

  ASSERT_EQ(vault_.SaveVault(path_), Result::kSuccess);

  struct stat st = {};

  ASSERT_EQ(stat(path_.c_str(), &st), 0);

  /* No group or other bits, and none of setuid, setgid or sticky */

  EXPECT_EQ(st.st_mode & 07077, 0u);

  /* The vault the tightened permissions belong to is still a vault that opens */

  EXPECT_EQ(Reload(), Result::kSuccess);
}

#endif /* !_WIN32 */

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
 * @brief   Verify entry contents survive a master password change and the reopen that follows
 */
TEST_F(VaultFileTest, ChangePWPreservesEntries) {
  Password pw = MakePW("entrypassword");

  ASSERT_EQ(vault_.CreateEntry("Google", "user@google.com", pw), Result::kSuccess);
  ASSERT_EQ(vault_.ChangePW(MakePW("asdf1234"), path_), Result::kSuccess);
  ASSERT_EQ(Reload("asdf1234"), Result::kSuccess);

  EXPECT_EQ(vault_.GetEntryCount(), 1);

  Password got;

  EXPECT_TRUE(vault_.GetEntryPW("Google", "user@google.com", got));
  EXPECT_TRUE(got.Equal(pw));
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
 * Header Authentication Test
 * ================================================== */

/**
 * @brief   Verify a vault whose header has one byte flipped never opens, and fails for the documented reason
 */
TEST_P(VaultHeaderTamperTest, FlippedHeaderByteIsRefused) {
  const size_t off = GetParam();

  std::vector<uint8_t> buff = ReadFile(path_);

  ASSERT_GE(buff.size(), kHeaderSize);

  buff[off] ^= 0xFF;

  WriteFile(path_, buff);

  /* The correct password, so what is on trial is the header and not the password */

  EXPECT_EQ(Reload(), Result::kFailure);
  EXPECT_NE(vault_.GetLastError().find(ExpectedMessage(off)), std::string::npos);
}

INSTANTIATE_TEST_SUITE_P(EveryHeaderByte, VaultHeaderTamperTest, testing::Range(size_t{ 0 }, kHeaderSize));

/**
 * @brief   Verify parameters edited to another accepted value are refused as well
 *
 * Out-of-range parameters are caught by the range check, which says nothing about the ones inside it. An edit from
 * one legal value to another survives validation and derives a different key, so what refuses it is the commitment,
 * and the vault reports it the way it reports any other derivation that does not match: as a wrong password.
 */
TEST_F(VaultFileTest, OpenRejectsInRangeKdfParamTamper) {
  const std::array<KdfParams, 3> cases{
    KdfParams{ .time_cost = kMinTimeCost + 1, .mem_cost = kMinMemCost, .parallelism = kMinParallelism },
    KdfParams{ .time_cost = kMinTimeCost, .mem_cost = kMinMemCost + 1024, .parallelism = kMinParallelism },
    KdfParams{ .time_cost = kMinTimeCost, .mem_cost = kMinMemCost, .parallelism = kMinParallelism + 1 },
  };

  for (const KdfParams& params : cases) {
    SCOPED_TRACE(testing::Message() << "t=" << params.time_cost << " m=" << params.mem_cost
                                    << " p=" << params.parallelism);

    MakeVaultWith(MinParams());

    ASSERT_EQ(Reload(), Result::kSuccess);

    PatchHeaderParams(params);

    EXPECT_EQ(Reload(), Result::kFailure);
    EXPECT_NE(vault_.GetLastError().find("Incorrect master password"), std::string::npos);
  }
}

/**
 * @brief   Verify a wrong password and a damaged vault are reported as different things
 *
 * The distinction the commitment exists to draw. Both used to arrive as one sentence, since a failing tag cannot say
 * which of the two it saw.
 */
TEST_F(VaultFileTest, WrongPasswordAndCorruptionDiffer) {
  ASSERT_EQ(vault_.CreateEntry("Google", "user@google.com", MakePW("password")), Result::kSuccess);
  ASSERT_EQ(vault_.SaveVault(path_), Result::kSuccess);

  /* Wrong password, intact file: settled by the commitment before anything is decrypted */

  EXPECT_EQ(Reload("asdf1234"), Result::kFailure);

  const std::string wrong_pw = vault_.GetLastError();

  /* Right password, one ciphertext byte flipped: the commitment matches and the tag does not */

  std::vector<uint8_t> buff = ReadFile(path_);

  ASSERT_GT(buff.size(), kHeaderSize + kIVSize);

  buff[kHeaderSize + kIVSize] ^= 0xFF;

  WriteFile(path_, buff);

  EXPECT_EQ(Reload(), Result::kFailure);

  const std::string corrupted = vault_.GetLastError();

  EXPECT_NE(wrong_pw.find("Incorrect master password"), std::string::npos);
  EXPECT_NE(corrupted.find("Vault file is corrupted"), std::string::npos);
  EXPECT_NE(wrong_pw, corrupted);
}

/**
 * @brief   Verify ParseHeader refuses a buffer shorter than a header
 *
 * Unreachable through Vault, which rejects anything below kMinSize before it reads, and checked here because the
 * module promises it to any other caller.
 */
TEST(VaultHeaderTest, ParseRejectsShortInput) {
  const std::vector<uint8_t> buff(kHeaderSize - 1, 0x00);

  VaultHeader header;

  EXPECT_EQ(ParseHeader(buff, header), HeaderStatus::kTooSmall);
  EXPECT_STRNE(HeaderErrorMessage(HeaderStatus::kTooSmall), "");
  EXPECT_STREQ(HeaderErrorMessage(HeaderStatus::kOk), "");
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
