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
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <vector>

#ifndef _WIN32
#include <sys/stat.h>
#include <unistd.h>
#endif

#ifdef _WIN32
#include "tests/win32_dacl.h"
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
   * @brief   Replace the file at a path with an empty vault built under the given parameters
   * @param   path    File path to write
   * @param   params  Argon2id parameters to derive with and record
   */
  static void MakeVaultAt(const std::string& path, const KdfParams& params) {
    std::vector<uint8_t> img(kCountSize);

    StoreLE32(img.data(), 0);

    std::array<uint8_t, kSaltSize> salt{};
    salt.fill(0x33);

    WriteVault(path, img, salt, params);
  }

  /**
   * @brief   Replace the vault file with an empty vault built under the given parameters
   * @param   params  Argon2id parameters to derive with and record
   */
  void MakeVaultWith(const KdfParams& params) { MakeVaultAt(path_, params); }

  /**
   * @brief   Replace the vault file with a cheap one and open the fixture's session on it
   *
   * What every concurrent-modification case starts from. The two sessions below each pay for an Argon2id derivation
   * to open, so the vault they open is written at the cheapest parameters a header may legally carry.
   */
  void MakeCheapVault() {
    MakeVaultWith(MinParams());

    ASSERT_EQ(Reload(), Result::kSuccess);
  }

  /**
   * @brief   Open a second session on the fixture's vault, as a second window on the same file would
   * @param   other   Vault to open
   */
  void OpenOther(Vault& other) const { ASSERT_EQ(other.OpenVault(path_, MakePW("password")), Result::kSuccess); }

  /**
   * @brief   Report whether a save temporary for a path is still sitting in its directory
   * @param   path    Vault file path
   * @return  true if a "<vault>.XXXXXX" file is there
   *
   * SaveVaultWith writes to path + ".XXXXXX" with the last six characters replaced, so a leftover is a file named
   * exactly that much longer than the vault. A refused save has to take its temporary with it: the directory is the
   * user's, and a vault that grows a litter of half-written copies every time another window saves first is its own
   * kind of data loss.
   */
  static bool TempFileLeft(const std::string& path) {
    const std::filesystem::path target(path);
    const std::filesystem::path dir = target.has_parent_path() ? target.parent_path() : std::filesystem::path(".");
    const std::string prefix = target.filename().string() + ".";

    for (const auto& item : std::filesystem::directory_iterator(dir)) {
      const std::string name = item.path().filename().string();

      if (name.size() == prefix.size() + 6 && name.starts_with(prefix)) {
        return true;
      }
    }

    return false;
  }

  /**
   * @brief   Report whether an entry is in a vault's entry set
   * @param   vault   Vault to look in
   * @param   site    Site name
   * @param   acc     Account
   * @return  true if the entry is there
   */
  static bool HasEntry(const Vault& vault, const std::string& site, const std::string& acc) {
    const auto& entries = vault.GetEntries();

    return entries.find({ .site = site, .acc = acc }) != entries.end();
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

/**
 * @brief   Verify creating a vault at a path an existing vault holds is refused, and that vault survives intact
 */
TEST_F(VaultFileTest, NewVaultRefusesExistingVault) {
  ASSERT_EQ(vault_.CreateEntry("Google", "user@google.com", MakePW("asdf1234")), Result::kSuccess);
  ASSERT_EQ(vault_.SaveVault(path_), SaveResult::kSuccess);

  /* A second session, which knows nothing about this path beyond the name it was given */

  Vault other;

  EXPECT_EQ(other.NewVault(path_, MakePW("otherpassword")), Result::kFailure);
  EXPECT_NE(other.GetLastError().find("already exists"), std::string::npos);

  /* What the path holds is still the vault that was saved: the original password opens it and the entry it was
   * saved with reads back, password included */

  EXPECT_EQ(Reload(), Result::kSuccess);
  EXPECT_EQ(vault_.GetEntryCount(), 1);

  Password got;

  EXPECT_TRUE(vault_.GetEntryPW("Google", "user@google.com", got));
  EXPECT_TRUE(got.Equal(MakePW("asdf1234")));
}

/**
 * @brief   Verify a file that is not a vault at all is refused and left byte for byte as it was
 */
TEST_F(VaultFileTest, NewVaultLeavesForeignFileUntouched) {
  const std::string notes_path = "notes.txt";
  const std::string text = "Shopping list, not a vault\n";

  /* Copying through the string's iterators would convert char to uint8_t per element, which MSVC reports as a
   * signed/unsigned mismatch from inside <xutility>; the pointer pair carries the element type the vector wants. */

  const auto* const text_bytes = reinterpret_cast<const uint8_t*>(text.data());
  const std::vector<uint8_t> notes(text_bytes, text_bytes + text.size());

  WriteFile(notes_path, notes);

  Vault other;

  EXPECT_EQ(other.NewVault(notes_path, MakePW("password")), Result::kFailure);
  EXPECT_NE(other.GetLastError().find("already exists"), std::string::npos);

  EXPECT_EQ(ReadFile(notes_path), notes);
  EXPECT_EQ(RemoveFile(notes_path), Result::kSuccess);
}

#ifndef _WIN32

/**
 * @brief   Verify a dangling symbolic link at the chosen path is refused, by the publish rather than by the check
 *
 * FileExists resolves the path it is given, so a link pointing at nothing reports as absent and the check NewVault
 * makes before deriving anything lets this path through. The refusal can therefore only come from the create-only
 * publish at the end, and the message is what says which of the two answered: "was taken" is reported by the rename
 * alone, so asserting on it is what makes this a test of the commit point rather than of the check above it. Under a
 * replacing rename the link would simply be overwritten, which is the mutation this case is here to catch.
 */
TEST_F(VaultFileTest, NewVaultRefusesDanglingSymlink) {
  const std::string link_path = "dangling.vault";

  RemoveFile(link_path);  // A link an earlier run left behind would fail the symlink below

  ASSERT_EQ(symlink("no_such_target", link_path.c_str()), 0);
  ASSERT_FALSE(FileExists(link_path));

  Vault other;

  EXPECT_EQ(other.NewVault(link_path, MakePW("password")), Result::kFailure);
  EXPECT_NE(other.GetLastError().find("was taken"), std::string::npos);

  /* The path still holds the link itself, so nothing was written over it or through it */

  struct stat st = {};

  ASSERT_EQ(lstat(link_path.c_str(), &st), 0);
  EXPECT_TRUE(S_ISLNK(st.st_mode));

  /* And the temporary the attempt wrote was cleaned up rather than left beside the link */

  const std::string prefix = link_path + ".";

  for (const auto& entry : std::filesystem::directory_iterator(".")) {
    EXPECT_FALSE(entry.path().filename().string().starts_with(prefix));
  }

  EXPECT_EQ(RemoveFile(link_path), Result::kSuccess);
}

/**
 * @brief   Verify a path whose existence cannot be established is refused before anything is derived
 *
 * The counterpart of the dangling link above. There the path resolves, to nothing, and the check lets it through;
 * here a pair of links pointing at each other resolves to neither a file nor an absence, and the check is what has
 * to answer, because a question the file system will not answer is not a free name. The refusal therefore lands
 * where the create's own message is, ahead of the password and the seconds of Argon2id behind it.
 */
TEST_F(VaultFileTest, NewVaultRefusesSymlinkLoop) {
  const std::string loop_a = "loop_a.vault";
  const std::string loop_b = "loop_b.vault";

  RemoveFile(loop_a);  // Links an earlier run left behind would fail the calls below
  RemoveFile(loop_b);

  ASSERT_EQ(symlink(loop_b.c_str(), loop_a.c_str()), 0);
  ASSERT_EQ(symlink(loop_a.c_str(), loop_b.c_str()), 0);

  Vault other;

  EXPECT_EQ(other.NewVault(loop_a, MakePW("password")), Result::kFailure);
  EXPECT_FALSE(other.GetLastError().empty());

  /* Both names still hold the links themselves, so nothing was written through the loop or over either of them */

  struct stat st = {};

  ASSERT_EQ(lstat(loop_a.c_str(), &st), 0);
  EXPECT_TRUE(S_ISLNK(st.st_mode));

  ASSERT_EQ(lstat(loop_b.c_str(), &st), 0);
  EXPECT_TRUE(S_ISLNK(st.st_mode));

  EXPECT_EQ(RemoveFile(loop_a), Result::kSuccess);
  EXPECT_EQ(RemoveFile(loop_b), Result::kSuccess);
}

#endif /* !_WIN32 */

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
 * @brief   Verify opening a vault whose image holds bytes past the last counted entry fails
 *
 * The count field and the bytes behind it are two statements about the same image, and a vault where they disagree
 * this way is the one case the open path used to accept. Reading by the count alone, the session looks whole: one
 * entry is listed and nothing reports a problem. What is not listed does not go away, though. The uncounted bytes
 * stay in the decrypted image for as long as the vault is open, every save is refused because they are there, and
 * the session is not dirty, so closing it warns about nothing. The one way out is to edit an entry, which rebuilds
 * the image from the entry set and drops those bytes without saying so. Refusing the file at open is what this test
 * pins down: the format is defined in one place, and the open path is held to it like the others.
 */
TEST_F(VaultFileTest, OpenRejectsTrailingBytes) {
  const char* epw = "password";
  const uint32_t pw_len = static_cast<uint32_t>(strlen(epw));

  const Entry counted{ .site = "Google", .acc = "user@google.com", .pw_len = pw_len };
  const Entry uncounted{ .site = "GitHub", .acc = "user@github.com", .pw_len = pw_len };

  std::span<const uint8_t> pw_span(reinterpret_cast<const uint8_t*>(epw), pw_len);

  /* Entry count is 1, but two well-formed entries follow it */

  std::vector<uint8_t> img(kCountSize + counted.Size() + uncounted.Size(), 0);

  StoreLE32(img.data(), 1);

  size_t cur = kCountSize;

  ASSERT_EQ(counted.Serialize(std::span(img).subspan(cur), pw_span), counted.Size());

  cur += counted.Size();

  ASSERT_EQ(uncounted.Serialize(std::span(img).subspan(cur), pw_span), uncounted.Size());

  /* Write a vault the fixture password opens, at the cheapest legal parameters, so the image is what fails and the
   * case does not spend a 512 MiB derivation saying so */

  std::array<uint8_t, kSaltSize> salt{};
  salt.fill(0x44);

  WriteVault(path_, img, salt, MinParams());

  EXPECT_EQ(Reload(), Result::kFailure);
  EXPECT_NE(vault_.GetLastError().find("Validation failed - Trailing bytes after final entry"), std::string::npos);
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
  ASSERT_EQ(vault_.SaveVault(path_), SaveResult::kSuccess);

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
  ASSERT_EQ(vault_.ChangePW(MakePW("asdf1234"), path_), SaveResult::kSuccess);

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

  ASSERT_EQ(vault_.SaveVault(path_), SaveResult::kSuccess);
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
 * The property that holds the CRUD layer and the file layer to each other. The suite covers each class thoroughly on
 * its own, which leaves a gap between them: an entry a byte under kMinEntrySize can be accepted, serialized,
 * encrypted and written perfectly well by classes none of which is wrong on its own, and refused on the way back in.
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

    /* A fresh vault per case, so each one is written and read on its own rather than on what the last case left.
       The path is cleared first because a create refuses a name that is already taken, and what holds it here is the
       fixture's own vault on the first pass and the previous case's on every one after it. */

    ASSERT_EQ(RemoveFile(path_), Result::kSuccess);
    ASSERT_EQ(vault_.NewVault(path_, MakePW("password")), Result::kSuccess) << vault_.GetLastError();

    for (const auto& rec : records) {
      ASSERT_EQ(vault_.CreateEntry(rec.site, rec.acc, MakePW(rec.pw.c_str())), Result::kSuccess)
          << vault_.GetLastError();
    }

    ASSERT_EQ(vault_.SaveVault(path_), SaveResult::kSuccess) << vault_.GetLastError();
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

  ASSERT_EQ(vault_.SaveVault(path_), SaveResult::kSuccess);
  std::vector<uint8_t> first = ReadFile(path_);

  ASSERT_EQ(vault_.SaveVault(path_), SaveResult::kSuccess);
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
 * the mode of the vault. Nothing copies the mode of the file being replaced onto it, so a vault left readable by
 * everybody does not stay that way through the saves that follow, and setuid, setgid and sticky are not carried
 * across either. This is the layer a user would feel that at, so the guarantee is pinned here as well as at
 * OpenTempFile.
 */
TEST_F(VaultFileTest, SaveDoesNotWidenVaultPermissions) {
  ASSERT_EQ(chmod(path_.c_str(), 0666), 0);

  ASSERT_EQ(vault_.SaveVault(path_), SaveResult::kSuccess);

  struct stat st = {};

  ASSERT_EQ(stat(path_.c_str(), &st), 0);

  /* No group or other bits, and none of setuid, setgid or sticky */

  EXPECT_EQ(st.st_mode & 07077, 0u);

  /* The vault the tightened permissions belong to is still a vault that opens */

  EXPECT_EQ(Reload(), Result::kSuccess);
}

#endif /* !_WIN32 */

#ifdef _WIN32

/**
 * @brief   Verify a save never widens the permissions of the vault it replaces
 *
 * The Windows half of the same guarantee. There is no mode word to loosen here, so what stands in for one is the
 * directory: one that offers Everyone an inheritable full-access ACE would hand that ACE to anything created in it
 * with a default security descriptor. Every vault file this program writes is created by OpenTempFile and published
 * by a rename within that same directory, and a rename carries the file's own descriptor rather than taking one from
 * where it lands, so the explicit DACL the temporary was created under is the DACL of the published vault.
 */
TEST_F(VaultFileTest, SaveDoesNotWidenVaultPermissions) {
  const std::string dir = "vault_inherit_dir";
  const std::string path = dir + "/child.vault";

  ASSERT_TRUE(MakeWorldAccessibleDir(dir));
  ASSERT_EQ(vault_.NewVault(path, MakePW("password")), Result::kSuccess);
  ASSERT_EQ(vault_.CreateEntry("Google", "user@google.com", MakePW("password")), Result::kSuccess);
  ASSERT_EQ(vault_.SaveVault(path), SaveResult::kSuccess);

  EXPECT_TRUE(CheckOwnerOnlyDacl(path));

  /* The vault those permissions belong to is still a vault that opens */

  vault_.CloseVault();

  Vault fresh;

  EXPECT_EQ(fresh.OpenVault(path, MakePW("password")), Result::kSuccess);
  EXPECT_EQ(fresh.GetEntryCount(), 1);

  fresh.CloseVault();

  EXPECT_EQ(RemoveFile(path), Result::kSuccess);
  EXPECT_TRUE(RemoveDirectoryW(ToWidePath(dir).c_str()));
}

#endif /* _WIN32 */

/**
 * @brief   Verify SaveVault fails when no vault is open
 */
TEST_F(VaultFileTest, SaveWithoutOpenVault) {
  vault_.CloseVault();

  EXPECT_EQ(vault_.SaveVault(path_), SaveResult::kError);
  EXPECT_NE(vault_.GetLastError().find("No vault is open"), std::string::npos);
}

/**
 * @brief   Verify ChangePW fails when no vault is open
 */
TEST_F(VaultFileTest, ChangePWWithoutOpenVault) {
  vault_.CloseVault();

  EXPECT_EQ(vault_.ChangePW(MakePW("asdf1234"), path_), SaveResult::kError);
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

  EXPECT_EQ(vault_.ChangePW(MakePW("asdf1234"), path_), SaveResult::kSuccess);
  EXPECT_EQ(Reload("asdf1234"), Result::kSuccess);
  EXPECT_EQ(vault_.GetEntryCount(), 1);
}

/**
 * @brief   Verify entry contents survive a master password change and the reopen that follows
 */
TEST_F(VaultFileTest, ChangePWPreservesEntries) {
  Password pw = MakePW("entrypassword");

  ASSERT_EQ(vault_.CreateEntry("Google", "user@google.com", pw), Result::kSuccess);
  ASSERT_EQ(vault_.ChangePW(MakePW("asdf1234"), path_), SaveResult::kSuccess);
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
  EXPECT_EQ(vault_.ChangePW(MakePW("asdf1234"), "no_such_dir/child.vault"), SaveResult::kError);

  EXPECT_TRUE(vault_.VerifyPW(MakePW("password")));
  EXPECT_FALSE(vault_.VerifyPW(MakePW("asdf1234")));
}

/* ==================================================
 * Unsaved Change Test
 * ================================================== */

/**
 * @brief   Verify created and opened vaults start clean, and what a close drops when one is not
 *
 * The reload is the failure the flag exists to announce: the unsaved entry is gone from the reopened vault, and
 * nothing but the flag said so beforehand.
 */
TEST_F(VaultFileTest, NewAndOpenedVaultsAreClean) {
  EXPECT_FALSE(vault_.IsDirty());

  ASSERT_EQ(vault_.CreateEntry("Google", "user@google.com", MakePW("password")), Result::kSuccess);
  ASSERT_TRUE(vault_.IsDirty());

  ASSERT_EQ(Reload(), Result::kSuccess);

  EXPECT_FALSE(vault_.IsDirty());
  EXPECT_EQ(vault_.GetEntryCount(), 0);
}

/**
 * @brief   Verify a save that publishes nothing keeps the vault dirty until one does
 *
 * The prompt offers to save before closing, and a save that fails at that point must not also clear the flag, or the
 * next close would drop the changes without asking.
 */
TEST_F(VaultFileTest, FailedSaveKeepsDirty) {
  ASSERT_EQ(vault_.CreateEntry("Google", "user@google.com", MakePW("password")), Result::kSuccess);

  EXPECT_EQ(vault_.SaveVault("no_such_dir/child.vault"), SaveResult::kError);
  EXPECT_TRUE(vault_.IsDirty());

  EXPECT_EQ(vault_.SaveVault(path_), SaveResult::kSuccess);
  EXPECT_FALSE(vault_.IsDirty());
}

/**
 * @brief   Verify a password change counts as a save of the pending edits
 *
 * ChangePW writes the current image under the new key, unsaved edits included, so after it the file already holds
 * them. The reload under the new password is what shows the flag was cleared for a reason.
 */
TEST_F(VaultFileTest, ChangePWClearsDirty) {
  ASSERT_EQ(vault_.CreateEntry("Google", "user@google.com", MakePW("password")), Result::kSuccess);
  ASSERT_TRUE(vault_.IsDirty());

  ASSERT_EQ(vault_.ChangePW(MakePW("asdf1234"), path_), SaveResult::kSuccess);
  EXPECT_FALSE(vault_.IsDirty());

  ASSERT_EQ(Reload("asdf1234"), Result::kSuccess);
  EXPECT_EQ(vault_.GetEntryCount(), 1);
}

/**
 * @brief   Verify a password change that publishes nothing keeps the vault dirty
 */
TEST_F(VaultFileTest, FailedChangePWKeepsDirty) {
  ASSERT_EQ(vault_.CreateEntry("Google", "user@google.com", MakePW("password")), Result::kSuccess);

  EXPECT_EQ(vault_.ChangePW(MakePW("asdf1234"), "no_such_dir/child.vault"), SaveResult::kError);
  EXPECT_TRUE(vault_.IsDirty());
}

/* ==================================================
 * Concurrent Modification Test
 * ================================================== */

/* Two Vault objects on one path stand for two windows on one vault. Each reads the file once and closes it, so
 * neither can see what the other does to it except by looking again, which is exactly the situation a save has to
 * survive. The IV is what tells them apart: every save this program makes draws a fresh one, so the bytes at
 * kHeaderSize identify the version a session is holding. */

/**
 * @brief   Verify a save is refused when another session published over the vault first
 *
 * The lost update this check exists for. Both sessions opened the same file, both hold edits the other cannot see,
 * and an atomic rename does nothing about it: it publishes whole files, and the second whole file simply has no
 * trace of the first one's work in it. Without the check both saves report success and one of them is a lie.
 */
TEST_F(VaultFileTest, SaveRefusesFileAnotherSessionWrote) {
  MakeCheapVault();

  Vault other;

  OpenOther(other);

  ASSERT_EQ(other.CreateEntry("Microsoft", "user@microsoft.com", MakePW("asdf1234")), Result::kSuccess);
  ASSERT_EQ(other.SaveVault(path_), SaveResult::kSuccess);

  const std::vector<uint8_t> before = ReadFile(path_);

  ASSERT_EQ(vault_.CreateEntry("Google", "user@google.com", MakePW("password")), Result::kSuccess);

  EXPECT_EQ(vault_.SaveVault(path_), SaveResult::kConflict);
  EXPECT_NE(vault_.GetLastError().find("changed on disk"), std::string::npos);

  /* Nothing was published, and the temporary the refused save had already written went with the refusal */

  EXPECT_EQ(ReadFile(path_), before);
  EXPECT_FALSE(TempFileLeft(path_));

  /* The refused session is untouched: it still holds its own edit and still knows the edit is unsaved, so the user
   * can answer the warning rather than having to reconstruct what they had */

  EXPECT_TRUE(vault_.IsDirty());
  EXPECT_EQ(vault_.GetEntryCount(), 1);
  EXPECT_TRUE(HasEntry(vault_, "Google", "user@google.com"));
}

/**
 * @brief   Verify an acknowledged save publishes over the version it was warned about
 */
TEST_F(VaultFileTest, AcknowledgedSaveOverwritesAnotherSessionsWork) {
  MakeCheapVault();

  Vault other;

  OpenOther(other);

  ASSERT_EQ(other.CreateEntry("Microsoft", "user@microsoft.com", MakePW("asdf1234")), Result::kSuccess);
  ASSERT_EQ(other.SaveVault(path_), SaveResult::kSuccess);

  ASSERT_EQ(vault_.CreateEntry("Google", "user@google.com", MakePW("password")), Result::kSuccess);
  ASSERT_EQ(vault_.SaveVault(path_), SaveResult::kConflict);

  EXPECT_EQ(vault_.SaveVault(path_, SaveMode::kOverwriteAcknowledged), SaveResult::kSuccess);
  EXPECT_FALSE(vault_.IsDirty());
  EXPECT_FALSE(TempFileLeft(path_));

  /* The overwrite is what it says it is. What comes back off the disk is this session's vault, and the other
   * session's entry went with the file that held it. */

  Vault fresh;

  ASSERT_EQ(fresh.OpenVault(path_, MakePW("password")), Result::kSuccess);
  EXPECT_EQ(fresh.GetEntryCount(), 1);
  EXPECT_TRUE(HasEntry(fresh, "Google", "user@google.com"));
  EXPECT_FALSE(HasEntry(fresh, "Microsoft", "user@microsoft.com"));
}

/**
 * @brief   Verify an acknowledgement covers the one version it was given for and no later one
 *
 * A prompt is answered by a person, which takes time, and the file can move again inside it. What the user agreed to
 * replace is the version they were shown; treating their answer as a standing permission would let the save destroy
 * something nobody ever described to them.
 */
TEST_F(VaultFileTest, AcknowledgementCoversOnlyTheVersionItWasGivenFor) {
  MakeCheapVault();

  Vault other;

  OpenOther(other);

  ASSERT_EQ(other.CreateEntry("Microsoft", "user@microsoft.com", MakePW("asdf1234")), Result::kSuccess);
  ASSERT_EQ(other.SaveVault(path_), SaveResult::kSuccess);

  ASSERT_EQ(vault_.CreateEntry("Google", "user@google.com", MakePW("password")), Result::kSuccess);
  ASSERT_EQ(vault_.SaveVault(path_), SaveResult::kConflict);

  /* The file moves on between the warning and the answer to it */

  ASSERT_EQ(other.CreateEntry("Amazon", "user@amazon.com", MakePW("qwerty12")), Result::kSuccess);
  ASSERT_EQ(other.SaveVault(path_), SaveResult::kSuccess);

  const std::vector<uint8_t> before = ReadFile(path_);

  EXPECT_EQ(vault_.SaveVault(path_, SaveMode::kOverwriteAcknowledged), SaveResult::kConflict);

  EXPECT_EQ(ReadFile(path_), before);
  EXPECT_FALSE(TempFileLeft(path_));

  /* That second refusal recorded what it saw, so the acknowledgement answering it is the one that goes through */

  EXPECT_EQ(vault_.SaveVault(path_, SaveMode::kOverwriteAcknowledged), SaveResult::kSuccess);
}

/**
 * @brief   Verify an acknowledgement with nothing to acknowledge is refused like any other save
 *
 * The mode is an answer to a warning, not a way of asking for one to be skipped. A caller that reaches for it without
 * having been refused first has nothing the user could have agreed to, so it is treated as the plain save it is.
 */
TEST_F(VaultFileTest, AcknowledgedSaveWithoutAWarningIsRefused) {
  MakeCheapVault();

  Vault other;

  OpenOther(other);

  ASSERT_EQ(other.CreateEntry("Microsoft", "user@microsoft.com", MakePW("asdf1234")), Result::kSuccess);
  ASSERT_EQ(other.SaveVault(path_), SaveResult::kSuccess);

  const std::vector<uint8_t> before = ReadFile(path_);

  ASSERT_EQ(vault_.CreateEntry("Google", "user@google.com", MakePW("password")), Result::kSuccess);

  EXPECT_EQ(vault_.SaveVault(path_, SaveMode::kOverwriteAcknowledged), SaveResult::kConflict);
  EXPECT_EQ(ReadFile(path_), before);

  /* That refusal is itself the warning, and the acknowledgement answering it goes through */

  EXPECT_EQ(vault_.SaveVault(path_, SaveMode::kOverwriteAcknowledged), SaveResult::kSuccess);
}

/**
 * @brief   Verify a save is refused when another session changed the master password
 *
 * The costliest version of the same loss. A save that went through here would put the vault back under the password
 * this session opened with, and whoever changed it elsewhere would be locked out of their own vault by a window they
 * were not looking at.
 */
TEST_F(VaultFileTest, SaveRefusesFileAnotherSessionChangedThePasswordOf) {
  MakeCheapVault();

  Vault other;

  OpenOther(other);

  ASSERT_EQ(other.ChangePW(MakePW("asdf1234"), path_), SaveResult::kSuccess);

  ASSERT_EQ(vault_.CreateEntry("Google", "user@google.com", MakePW("password")), Result::kSuccess);

  EXPECT_EQ(vault_.SaveVault(path_), SaveResult::kConflict);
  EXPECT_FALSE(TempFileLeft(path_));

  /* The file still belongs to the password it was changed to */

  Vault fresh;

  EXPECT_EQ(fresh.OpenVault(path_, MakePW("asdf1234")), Result::kSuccess);
}

/**
 * @brief   Verify a password change is refused when another session published over the vault first
 *
 * Refused before the derivation rather than after it, so the report arrives at the moment the user asked rather than
 * at the end of several seconds of Argon2id spent on a file that was never going to be written. The session keeps
 * the key it had either way.
 */
TEST_F(VaultFileTest, ChangePWRefusesFileAnotherSessionWrote) {
  MakeCheapVault();

  Vault other;

  OpenOther(other);

  ASSERT_EQ(other.CreateEntry("Microsoft", "user@microsoft.com", MakePW("asdf1234")), Result::kSuccess);
  ASSERT_EQ(other.SaveVault(path_), SaveResult::kSuccess);

  const std::vector<uint8_t> before = ReadFile(path_);

  EXPECT_EQ(vault_.ChangePW(MakePW("qwerty12"), path_), SaveResult::kConflict);

  EXPECT_EQ(ReadFile(path_), before);
  EXPECT_FALSE(TempFileLeft(path_));

  EXPECT_TRUE(vault_.VerifyPW(MakePW("password")));
  EXPECT_FALSE(vault_.VerifyPW(MakePW("qwerty12")));
}

/**
 * @brief   Verify a save is refused when the vault file is gone, and recreates it once acknowledged
 *
 * A missing file is not a free path to write onto. It may have been deleted on purpose, or moved, or be missing
 * because the volume holding it is not mounted, and quietly recreating it turns any of those into a vault appearing
 * where the user thought they had removed one.
 */
TEST_F(VaultFileTest, SaveRefusesMissingFileUntilAcknowledged) {
  MakeCheapVault();

  ASSERT_EQ(vault_.CreateEntry("Google", "user@google.com", MakePW("password")), Result::kSuccess);
  ASSERT_EQ(RemoveFile(path_), Result::kSuccess);

  EXPECT_EQ(vault_.SaveVault(path_), SaveResult::kConflict);
  EXPECT_FALSE(FileExists(path_));
  EXPECT_FALSE(TempFileLeft(path_));

  EXPECT_EQ(vault_.SaveVault(path_, SaveMode::kOverwriteAcknowledged), SaveResult::kSuccess);
  EXPECT_TRUE(FileExists(path_));

  Vault fresh;

  ASSERT_EQ(fresh.OpenVault(path_, MakePW("password")), Result::kSuccess);
  EXPECT_TRUE(HasEntry(fresh, "Google", "user@google.com"));
}

/**
 * @brief   Verify a save is refused when a backup has been restored over the vault
 *
 * What the file holds is a perfectly valid vault under the same password; it is simply older than the one this
 * session published. Nothing about the file itself says so, which is why the comparison is against what the session
 * last wrote rather than against anything the file claims about itself.
 */
TEST_F(VaultFileTest, SaveRefusesRestoredOlderCopy) {
  const std::vector<uint8_t> backup = ReadFile(path_);

  ASSERT_EQ(vault_.CreateEntry("Google", "user@google.com", MakePW("password")), Result::kSuccess);
  ASSERT_EQ(vault_.SaveVault(path_), SaveResult::kSuccess);

  WriteFile(path_, backup);

  ASSERT_EQ(vault_.CreateEntry("Microsoft", "user@microsoft.com", MakePW("asdf1234")), Result::kSuccess);

  EXPECT_EQ(vault_.SaveVault(path_), SaveResult::kConflict);
  EXPECT_EQ(ReadFile(path_), backup);
  EXPECT_FALSE(TempFileLeft(path_));
}

/**
 * @brief   Verify a save goes through when the file was put back to the exact version this session read
 *
 * The limit of comparing an IV, pinned here so that it is a decision rather than an oversight. Another session wrote
 * in between, and the check does not notice, because by the time the save runs the bytes at the path are the version
 * this session is holding. Nothing is lost by writing over them: what the intervening save produced is already gone,
 * taken by whoever restored these bytes, and this check is about the file rather than about the history of it.
 */
TEST_F(VaultFileTest, SaveAcceptsFileRestoredToTheVersionItRead) {
  MakeCheapVault();

  const std::vector<uint8_t> opened = ReadFile(path_);

  Vault other;

  OpenOther(other);

  ASSERT_EQ(other.CreateEntry("Microsoft", "user@microsoft.com", MakePW("asdf1234")), Result::kSuccess);
  ASSERT_EQ(other.SaveVault(path_), SaveResult::kSuccess);

  WriteFile(path_, opened);

  ASSERT_EQ(vault_.CreateEntry("Google", "user@google.com", MakePW("password")), Result::kSuccess);

  EXPECT_EQ(vault_.SaveVault(path_), SaveResult::kSuccess);

  Vault fresh;

  ASSERT_EQ(fresh.OpenVault(path_, MakePW("password")), Result::kSuccess);
  EXPECT_TRUE(HasEntry(fresh, "Google", "user@google.com"));
}

/**
 * @brief   Verify a save is refused when the file is too short for an IV to be read out of it
 *
 * A file that cannot be asked which version it is has to answer as a different one. "Nothing could be read, so carry
 * on" is the single answer this check must never give, since every way of failing to read reaches it.
 */
TEST_F(VaultFileTest, SaveRefusesFileTooShortToHoldAnIV) {
  std::vector<uint8_t> stub = ReadFile(path_);

  ASSERT_GT(stub.size(), kHeaderSize + kIVSize);

  stub.resize(kHeaderSize + kIVSize - 1);

  WriteFile(path_, stub);

  ASSERT_EQ(vault_.CreateEntry("Google", "user@google.com", MakePW("password")), Result::kSuccess);

  EXPECT_EQ(vault_.SaveVault(path_), SaveResult::kConflict);
  EXPECT_EQ(ReadFile(path_), stub);
  EXPECT_FALSE(TempFileLeft(path_));
}

/**
 * @brief   Verify a save onto a path holding a file this session never read is refused
 *
 * There is no version to compare against on a path the session has not opened, so existence is the whole of the
 * question. Whatever holds the name belongs to somebody, and this session has never seen it.
 */
TEST_F(VaultFileTest, SaveRefusesPathHoldingAFileThisSessionNeverRead) {
  const std::string other_path = "unread.vault";
  const std::string text = "Not this session's vault\n";

  /* Copying through the string's iterators would convert char to uint8_t per element, which MSVC reports as a
   * signed/unsigned mismatch from inside <xutility>; the pointer pair carries the element type the vector wants. */

  const auto* const text_bytes = reinterpret_cast<const uint8_t*>(text.data());
  const std::vector<uint8_t> notes(text_bytes, text_bytes + text.size());

  WriteFile(other_path, notes);

  EXPECT_EQ(vault_.SaveVault(other_path), SaveResult::kConflict);
  EXPECT_EQ(ReadFile(other_path), notes);
  EXPECT_FALSE(TempFileLeft(other_path));

  EXPECT_EQ(RemoveFile(other_path), Result::kSuccess);
}

/**
 * @brief   Verify a save onto a free path leaves the session following the file it made there
 *
 * Nothing holds the name, so this save is not replacing a version anybody owns and goes ahead. What it publishes is
 * the file the name now leads to, and the save after it has to recognise that file as the one this session wrote.
 * Resolving the name at one publish while comparing an unresolved one at the next would report a conflict against
 * the session's own work, and ask the user to acknowledge a file only they had ever written.
 */
TEST_F(VaultFileTest, SaveOntoAFreePathFollowsTheFileItMade) {
  const std::string other_path = "unheld.vault";

  RemoveFile(other_path);  // A file an earlier run left behind would make this a different case

  ASSERT_EQ(vault_.CreateEntry("Google", "user@google.com", MakePW("password")), Result::kSuccess);
  ASSERT_EQ(vault_.SaveVault(other_path), SaveResult::kSuccess);

  EXPECT_EQ(vault_.SaveVault(other_path), SaveResult::kSuccess);
  EXPECT_FALSE(vault_.IsDirty());
  EXPECT_FALSE(TempFileLeft(other_path));

  Vault fresh;

  ASSERT_EQ(fresh.OpenVault(other_path, MakePW("password")), Result::kSuccess);
  EXPECT_TRUE(HasEntry(fresh, "Google", "user@google.com"));

  fresh.CloseVault();

  EXPECT_EQ(RemoveFile(other_path), Result::kSuccess);
}

/* ==================================================
 * Symbolic Link Test
 * ================================================== */

#ifndef _WIN32

namespace {

/**
 * @brief   Report whether a path holds a symbolic link itself
 * @param   path    Path to look at
 * @return  true if the path is a link rather than whatever it leads to
 *
 * lstat rather than stat, because what every case below is about is the link surviving a save that went through it.
 * A stat would follow the link and report on the file at the far end, which says nothing about the link.
 */
bool IsSymlink(const std::string& path) {
  struct stat st = {};

  return lstat(path.c_str(), &st) == 0 && S_ISLNK(st.st_mode);
}

/**
 * @brief   List the names sitting beside a path that a save temporary for it would be among
 * @param   path    Vault file path
 * @return  The names in the path's directory that begin with the file's own name and a dot, in order
 *
 * Taken twice and compared, rather than TempFileLeft's single look, for the case below. TempFileLeft asks about the
 * one name shape SaveVaultWith writes, which is the right question when what is in doubt is whether that temporary
 * was cleaned up. What is in doubt below is whether the refusal left the directory as it found it at all, so the
 * whole prefix is listed, and comparing two listings is what keeps anything the case itself put there from counting
 * as a leftover.
 */
std::vector<std::string> NamesBeside(const std::string& path) {
  const std::filesystem::path target(path);
  const std::filesystem::path dir = target.has_parent_path() ? target.parent_path() : std::filesystem::path(".");
  const std::string prefix = target.filename().string() + ".";

  std::vector<std::string> names;

  for (const auto& item : std::filesystem::directory_iterator(dir)) {
    std::string name = item.path().filename().string();

    if (name.starts_with(prefix)) {
      names.push_back(std::move(name));
    }
  }

  /* directory_iterator hands names back in whatever order the file system holds them, which is not an order two
   * listings of the same directory have to agree on */

  std::ranges::sort(names);

  return names;
}

}  // namespace

/**
 * @brief   Verify a save through a symbolic link replaces the file the link leads to, not the link
 *
 * A vault kept in a synced folder and reached through a link in the home directory is the ordinary shape of this. The
 * publish is a rename, and a rename onto the link's own path replaces the link, so the file the user's path leads to
 * would keep the version it had while the link turned into a regular file holding the new one. Both halves are
 * asserted: the link is still a link, and the file at the far end is where the entry landed.
 */
TEST_F(VaultFileTest, SaveThroughSymlinkWritesTarget) {
  const std::string dir = "symlink_dir";
  const std::string target = dir + "/real.vault";
  const std::string link = "symlink.vault";

  ASSERT_EQ(mkdir(dir.c_str(), 0700), 0);

  MakeVaultAt(target, MinParams());

  RemoveFile(link);  // A link an earlier run left behind would fail the symlink below

  ASSERT_EQ(symlink(target.c_str(), link.c_str()), 0);
  ASSERT_EQ(vault_.OpenVault(link, MakePW("password")), Result::kSuccess);
  ASSERT_EQ(vault_.CreateEntry("Google", "user@google.com", MakePW("password")), Result::kSuccess);

  EXPECT_EQ(vault_.SaveVault(link), SaveResult::kSuccess);
  EXPECT_FALSE(vault_.IsDirty());

  /* The link is still a link, and the temporary was published out of the target's directory rather than left in
   * either of the two */

  EXPECT_TRUE(IsSymlink(link));
  EXPECT_FALSE(TempFileLeft(link));
  EXPECT_FALSE(TempFileLeft(target));

  vault_.CloseVault();

  /* The entry is in the file the link leads to, opened by that file's own path rather than through the link */

  Vault fresh;

  ASSERT_EQ(fresh.OpenVault(target, MakePW("password")), Result::kSuccess);
  EXPECT_EQ(fresh.GetEntryCount(), 1);
  EXPECT_TRUE(HasEntry(fresh, "Google", "user@google.com"));

  fresh.CloseVault();

  EXPECT_EQ(RemoveFile(link), Result::kSuccess);
  EXPECT_EQ(RemoveFile(target), Result::kSuccess);
  EXPECT_EQ(rmdir(dir.c_str()), 0);
}

/**
 * @brief   Verify a save follows a chain of relative links to the file at the end of it
 *
 * Every hop is resolved rather than the first one alone, and a relative target is read against the directory of the
 * link that stores it rather than against the working directory. "../mid.vault" held in links/ has to reach the
 * mid-chain link in the parent, and the rename has to land on the file at the far end, in a directory neither link
 * sits in.
 */
TEST_F(VaultFileTest, SaveThroughRelativeSymlinkChainWritesTarget) {
  const std::string link_dir = "chain_links";
  const std::string target_dir = "chain_target";
  const std::string target = target_dir + "/real.vault";
  const std::string mid = "mid.vault";
  const std::string link = link_dir + "/linked.vault";

  ASSERT_EQ(mkdir(link_dir.c_str(), 0700), 0);
  ASSERT_EQ(mkdir(target_dir.c_str(), 0700), 0);

  MakeVaultAt(target, MinParams());

  RemoveFile(mid);
  RemoveFile(link);

  /* Each target is stored relative to the directory of the link that holds it: the working directory's link names the
   * vault below it, and the one inside links/ has to climb out of that directory to name the first link */

  ASSERT_EQ(symlink(target.c_str(), mid.c_str()), 0);
  ASSERT_EQ(symlink(("../" + mid).c_str(), link.c_str()), 0);
  ASSERT_EQ(vault_.OpenVault(link, MakePW("password")), Result::kSuccess);
  ASSERT_EQ(vault_.CreateEntry("Google", "user@google.com", MakePW("password")), Result::kSuccess);

  EXPECT_EQ(vault_.SaveVault(link), SaveResult::kSuccess);

  /* Both hops came through it, and none of the three directories the chain passes through was left a temporary */

  EXPECT_TRUE(IsSymlink(link));
  EXPECT_TRUE(IsSymlink(mid));
  EXPECT_FALSE(TempFileLeft(link));
  EXPECT_FALSE(TempFileLeft(mid));
  EXPECT_FALSE(TempFileLeft(target));

  vault_.CloseVault();

  Vault fresh;

  ASSERT_EQ(fresh.OpenVault(target, MakePW("password")), Result::kSuccess);
  EXPECT_EQ(fresh.GetEntryCount(), 1);
  EXPECT_TRUE(HasEntry(fresh, "Google", "user@google.com"));

  fresh.CloseVault();

  EXPECT_EQ(RemoveFile(link), Result::kSuccess);
  EXPECT_EQ(RemoveFile(mid), Result::kSuccess);
  EXPECT_EQ(RemoveFile(target), Result::kSuccess);
  EXPECT_EQ(rmdir(link_dir.c_str()), 0);
  EXPECT_EQ(rmdir(target_dir.c_str()), 0);
}

/**
 * @brief   Verify a password change through a symbolic link re-encrypts the file the link leads to
 *
 * ChangePW publishes through the commit point a save does, and it asks about the file twice: once before the
 * derivation and once before the rename. All three have to mean the same file, or a check would clear one file and
 * the rename would take another.
 */
TEST_F(VaultFileTest, ChangePWThroughSymlinkWritesTarget) {
  const std::string dir = "changepw_link_dir";
  const std::string target = dir + "/real.vault";
  const std::string link = "changepw_link.vault";

  ASSERT_EQ(mkdir(dir.c_str(), 0700), 0);

  MakeVaultAt(target, MinParams());

  RemoveFile(link);

  ASSERT_EQ(symlink(target.c_str(), link.c_str()), 0);
  ASSERT_EQ(vault_.OpenVault(link, MakePW("password")), Result::kSuccess);

  EXPECT_EQ(vault_.ChangePW(MakePW("asdf1234"), link), SaveResult::kSuccess);
  EXPECT_TRUE(IsSymlink(link));
  EXPECT_FALSE(TempFileLeft(link));
  EXPECT_FALSE(TempFileLeft(target));

  vault_.CloseVault();

  /* The new password belongs to the file at the far end, and the old one does not open it any more */

  Vault fresh;

  EXPECT_EQ(fresh.OpenVault(target, MakePW("password")), Result::kFailure);
  EXPECT_EQ(fresh.OpenVault(target, MakePW("asdf1234")), Result::kSuccess);

  fresh.CloseVault();

  EXPECT_EQ(RemoveFile(link), Result::kSuccess);
  EXPECT_EQ(RemoveFile(target), Result::kSuccess);
  EXPECT_EQ(rmdir(dir.c_str()), 0);
}

/**
 * @brief   Verify an acknowledged save puts back a target that was deleted from under the link
 *
 * A dangling link resolves to nothing, so the file to publish onto cannot be read off the path any more. What answers
 * instead is the file this session read, which is the one the link was pointing at, so an acknowledged overwrite puts
 * the vault back where the link leads and the link works again. Writing it to the link's own path would leave the
 * target still missing and replace the link with a regular file.
 */
TEST_F(VaultFileTest, SaveAfterTargetDeletedRecreatesTarget) {
  const std::string dir = "deleted_target_dir";
  const std::string target = dir + "/real.vault";
  const std::string link = "deleted_target.vault";

  ASSERT_EQ(mkdir(dir.c_str(), 0700), 0);

  MakeVaultAt(target, MinParams());

  RemoveFile(link);

  ASSERT_EQ(symlink(target.c_str(), link.c_str()), 0);
  ASSERT_EQ(vault_.OpenVault(link, MakePW("password")), Result::kSuccess);
  ASSERT_EQ(vault_.CreateEntry("Google", "user@google.com", MakePW("password")), Result::kSuccess);
  ASSERT_EQ(RemoveFile(target), Result::kSuccess);

  /* A vault that is not there is not the version this session read, so the first save reports it rather than
   * recreating a file the user may have moved deliberately */

  EXPECT_EQ(vault_.SaveVault(link), SaveResult::kConflict);
  EXPECT_FALSE(FileExists(target));
  EXPECT_TRUE(vault_.IsDirty());

  EXPECT_EQ(vault_.SaveVault(link, SaveMode::kOverwriteAcknowledged), SaveResult::kSuccess);
  EXPECT_TRUE(FileExists(target));
  EXPECT_TRUE(IsSymlink(link));
  EXPECT_FALSE(TempFileLeft(link));
  EXPECT_FALSE(TempFileLeft(target));

  vault_.CloseVault();

  /* The link leads to a vault again, and the vault is this session's */

  Vault fresh;

  ASSERT_EQ(fresh.OpenVault(link, MakePW("password")), Result::kSuccess);
  EXPECT_EQ(fresh.GetEntryCount(), 1);
  EXPECT_TRUE(HasEntry(fresh, "Google", "user@google.com"));

  fresh.CloseVault();

  EXPECT_EQ(RemoveFile(link), Result::kSuccess);
  EXPECT_EQ(RemoveFile(target), Result::kSuccess);
  EXPECT_EQ(rmdir(dir.c_str()), 0);
}

/**
 * @brief   Verify a link repointed under an open session conflicts rather than publishing unseen
 *
 * The path is resolved afresh at every publish rather than pinned when the vault was opened, which is what lets a
 * save follow a link the user has since repointed. The file it now leads to is not the one this session read, so it
 * is a changed file in the same sense a changed IV is, and it is reported before anything is written. A session that
 * pinned its file at open would answer kSuccess here and write the old one, leaving the user's own path at a vault
 * without their change.
 */
TEST_F(VaultFileTest, SaveAfterLinkRetargetIsConflict) {
  const std::string first = "retarget_a.vault";
  const std::string second = "retarget_b.vault";
  const std::string link = "retarget_link.vault";

  MakeVaultAt(first, MinParams());
  MakeVaultAt(second, MinParams());

  RemoveFile(link);

  ASSERT_EQ(symlink(first.c_str(), link.c_str()), 0);
  ASSERT_EQ(vault_.OpenVault(link, MakePW("password")), Result::kSuccess);

  const std::vector<uint8_t> before_first = ReadFile(first);
  const std::vector<uint8_t> before_second = ReadFile(second);

  /* The user repoints the link while the session is open, which is a thing a person does between two saves */

  ASSERT_EQ(RemoveFile(link), Result::kSuccess);
  ASSERT_EQ(symlink(second.c_str(), link.c_str()), 0);
  ASSERT_EQ(vault_.CreateEntry("Google", "user@google.com", MakePW("password")), Result::kSuccess);

  EXPECT_EQ(vault_.SaveVault(link), SaveResult::kConflict);
  EXPECT_NE(vault_.GetLastError().find("changed on disk"), std::string::npos);

  /* Neither vault was touched, the temporary went with the refusal, and the session still holds the edit */

  EXPECT_EQ(ReadFile(first), before_first);
  EXPECT_EQ(ReadFile(second), before_second);
  EXPECT_FALSE(TempFileLeft(link));
  EXPECT_TRUE(vault_.IsDirty());

  EXPECT_EQ(vault_.SaveVault(link, SaveMode::kOverwriteAcknowledged), SaveResult::kSuccess);

  /* The acknowledged save published where the link leads now, and the file it used to lead to is as it was */

  EXPECT_EQ(ReadFile(first), before_first);

  vault_.CloseVault();

  Vault fresh;

  ASSERT_EQ(fresh.OpenVault(link, MakePW("password")), Result::kSuccess);
  EXPECT_EQ(fresh.GetEntryCount(), 1);
  EXPECT_TRUE(HasEntry(fresh, "Google", "user@google.com"));

  fresh.CloseVault();

  EXPECT_EQ(RemoveFile(link), Result::kSuccess);
  EXPECT_EQ(RemoveFile(first), Result::kSuccess);
  EXPECT_EQ(RemoveFile(second), Result::kSuccess);
}

/**
 * @brief   Verify a save onto a path that cannot be examined is refused, with the edit and the directory intact
 *
 * The save path's own version of the rule the check states. The temporary has been written, synced and closed by the
 * time the file at the far end is looked at, so a path the file system will not answer about has to come back as a
 * reason to refuse: the last look before the rename is the only thing standing between an unexaminable file and a
 * publish over it, and a look that cannot be made has established nothing.
 *
 * What is asserted after the refusal is the cost of it. The edit is still in the session, so the user has lost
 * nothing they could not save again, and the directory holds exactly the names it held before, so the temporary this
 * attempt wrote was taken away with it rather than left beside the vault.
 */
TEST_F(VaultFileTest, SaveRefusesSymlinkLoop) {
  const std::string loop = "save_loop.vault";

  ASSERT_EQ(vault_.CreateEntry("Google", "user@google.com", MakePW("password")), Result::kSuccess);

  /* The vault this session is holding is replaced, at its own name, by a pair of links pointing at each other. A user
   * reaches this by repointing a link they keep their vault behind while a window is open on it. */

  RemoveFile(loop);  // A link an earlier run left behind would fail the calls below

  ASSERT_EQ(RemoveFile(path_), Result::kSuccess);
  ASSERT_EQ(symlink(loop.c_str(), path_.c_str()), 0);
  ASSERT_EQ(symlink(path_.c_str(), loop.c_str()), 0);

  const std::vector<std::string> before = NamesBeside(path_);

  EXPECT_EQ(vault_.SaveVault(path_), SaveResult::kConflict);
  EXPECT_NE(vault_.GetLastError().find("changed on disk"), std::string::npos);

  EXPECT_TRUE(vault_.IsDirty());
  EXPECT_EQ(NamesBeside(path_), before);

  /* And the path still holds the link itself, so nothing was published over it either */

  EXPECT_TRUE(IsSymlink(path_));

  EXPECT_EQ(RemoveFile(loop), Result::kSuccess);
}

#endif /* !_WIN32 */

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

#ifndef _WIN32

/**
 * @brief   Verify a password change that published its file switches the session even when the directory sync fails
 *
 * A directory left writable and searchable but not readable is the cheapest way to reach the branch past the commit
 * point: mkstemp and rename need write and search, and the open SyncDir performs needs read. By the time it runs the
 * file already belongs to the new password, so the change is a success carrying a warning, and the session has to
 * follow the file rather than keep a key the file no longer opens with. Skipped as root, whose permission checks
 * these bits do not bind.
 */
TEST_F(VaultFileTest, PublishedChangePWSurvivesDirectorySyncFailure) {
  if (geteuid() == 0) {
    GTEST_SKIP() << "Directory permissions do not bind root";
  }

  const std::string dir = "sync_fail_dir";
  const std::string path = dir + "/child.vault";

  ASSERT_EQ(mkdir(dir.c_str(), 0700), 0);
  ASSERT_EQ(vault_.NewVault(path, MakePW("password")), Result::kSuccess);
  ASSERT_EQ(vault_.CreateEntry("Google", "user@google.com", MakePW("password")), Result::kSuccess);
  ASSERT_EQ(chmod(dir.c_str(), 0300), 0);

  EXPECT_EQ(vault_.ChangePW(MakePW("asdf1234"), path), SaveResult::kSuccess);
  EXPECT_FALSE(vault_.GetLastWarning().empty());
  EXPECT_FALSE(vault_.IsDirty());
  EXPECT_TRUE(vault_.VerifyPW(MakePW("asdf1234")));

  /* A save that follows keeps the file on the new password instead of reverting it to the old one */

  EXPECT_EQ(vault_.SaveVault(path), SaveResult::kSuccess);

  ASSERT_EQ(chmod(dir.c_str(), 0700), 0);

  Vault fresh;

  EXPECT_EQ(fresh.OpenVault(path, MakePW("asdf1234")), Result::kSuccess);
  EXPECT_EQ(fresh.GetEntryCount(), 1);

  fresh.CloseVault();
  vault_.CloseVault();

  EXPECT_EQ(RemoveFile(path), Result::kSuccess);
  EXPECT_EQ(rmdir(dir.c_str()), 0);
}

#endif /* !_WIN32 */

/**
 * @brief   Verify a wrong password and a damaged vault are reported as different things
 *
 * The distinction the commitment exists to draw: a failing tag on its own cannot say which of the two it saw, so
 * without it both arrive as one sentence.
 */
TEST_F(VaultFileTest, WrongPasswordAndCorruptionDiffer) {
  ASSERT_EQ(vault_.CreateEntry("Google", "user@google.com", MakePW("password")), Result::kSuccess);
  ASSERT_EQ(vault_.SaveVault(path_), SaveResult::kSuccess);

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
 * @brief   Verify GetLastError returns error message on failure
 */
TEST_F(VaultFileTest, GetLastError) {
  vault_.CloseVault();

  vault_.OpenVault("nonexistent.vault", MakePW("password"));

  EXPECT_FALSE(vault_.GetLastError().empty());
}
