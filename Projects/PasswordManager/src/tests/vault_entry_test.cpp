/**
 * @file    vault_entry_test.cpp
 * @brief   Unit tests for Vault entry management functions
 * @author  Astatine387
 */

#include <gtest/gtest.h>

#include <cstddef>
#include <cstring>
#include <string>
#include <vector>

#include "common/constants.h"
#include "core/vault.h"
#include "utils/platform.h"

namespace {

/**
 * @struct  EntryView
 * @brief   Everything a caller can observe about one entry
 *
 * The password is carried beside the two key fields on purpose. A rebuild that loses track of an offset leaves the
 * site and the account perfectly intact and hands back a neighbour's bytes for the password, so a comparison that
 * stops at the keys is the one comparison that cannot see the failure this is written for.
 */
struct EntryView {
  std::string site;
  std::string acc;
  std::string pw;

  bool operator==(const EntryView& other) const = default;
};

}  // namespace

/**
 * @class   VaultEntryTest
 * @brief   Test fixture for Vault entry CRUD operations
 *
 * Entry CRUD operates on the in-memory image and does not require an open
 * session key, so the fixture creates entries directly.
 */
class VaultEntryTest : public ::testing::Test {
 protected:
  Vault vault_;
  std::string path_ = "vault_entry_test.vault";

  /**
   * @brief   Remove the vault file, for the tests that write one
   *
   * Named apart from the file suite's own temporary so that the two cannot collide.
   */
  void TearDown() override { RemoveFile(path_); }

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
   * @brief   Build a field of a given byte length
   * @param   len     Length in bytes
   * @return  String of len repeated characters
   *
   * The parenthesized constructor is deliberate: a braced list selects basic_string(initializer_list<char>), which
   * narrows len to a char and builds a two character string instead of a field of len bytes.
   */
  // NOLINTNEXTLINE(modernize-return-braced-init-list)
  static std::string Field(int len) { return std::string(static_cast<size_t>(len), 'a'); }

  /**
   * @brief   Read every entry back through the public accessors
   * @return  Site, account and password of each entry, in entry set order
   *
   * Goes through GetEntryPW rather than reading the image, so the offsets are followed exactly as a caller would
   * follow them and a stale one shows up as the wrong password rather than being stepped over.
   */
  std::vector<EntryView> Snapshot() {
    std::vector<EntryView> res;

    for (const auto& entry : vault_.GetEntries()) {
      Password pw;

      EXPECT_TRUE(vault_.GetEntryPW(entry.site, entry.acc, pw));

      res.push_back({ .site = entry.site,
                      .acc = entry.acc,
                      .pw = (pw.GetSize() > 0) ? std::string(pw.GetData(), pw.GetSize()) : std::string() });
    }

    return res;
  }
};

/* ==================================================
 * Create Entry Test
 * ================================================== */

/**
 * @brief   Verify creating a single entry succeeds
 */
TEST_F(VaultEntryTest, CreateSingle) {
  Result res = vault_.CreateEntry("Google", "user@google.com", MakePW("password"));

  EXPECT_EQ(res, Result::kSuccess);
  EXPECT_EQ(vault_.GetEntryCount(), 1);
}

/**
 * @brief   Verify creating multiple unique entries succeeds
 */
TEST_F(VaultEntryTest, CreateMultiple) {
  vault_.CreateEntry("Google", "user1@google.com", MakePW("password"));
  vault_.CreateEntry("Microsoft", "user2@microsoft.com", MakePW("asdf1234"));
  vault_.CreateEntry("Amazon", "user3@amazon.com", MakePW("qwerty"));

  EXPECT_EQ(vault_.GetEntryCount(), 3);
}

/**
 * @brief   Verify creating a duplicate entry fails
 */
TEST_F(VaultEntryTest, CreateDuplicate) {
  vault_.CreateEntry("Google", "user@google.com", MakePW("password"));

  Result res = vault_.CreateEntry("Google", "user@google.com", MakePW("asdf1234"));

  EXPECT_EQ(res, Result::kFailure);
  EXPECT_EQ(vault_.GetEntryCount(), 1);
}

/**
 * @brief   Verify a created entry's password is stored in the image
 */
TEST_F(VaultEntryTest, CreateStoresPassword) {
  vault_.CreateEntry("Google", "user@google.com", MakePW("s3cr3t!!"));

  Password got;

  EXPECT_TRUE(vault_.GetEntryPW("Google", "user@google.com", got));
  EXPECT_TRUE(got.Equal(MakePW("s3cr3t!!")));
}

/* ==================================================
 * Field Validation Test
 * ================================================== */

/* Entry::Deserialize refuses a site, account or password past its ceiling, so an entry built out of longer fields
 * would go into an image the same parser cannot read back. These check that the core refuses such fields itself,
 * rather than leaving the format's invariant to the dialog that used to be the only thing enforcing it.
 *
 * Each case reads the reported reason as well as the return value, since a Result alone cannot tell an empty site
 * apart from an oversized one and it is the distinct reasons that make the rejection worth anything to a caller. */

/**
 * @brief   Verify creating an entry with an oversized site name fails
 */
TEST_F(VaultEntryTest, CreateEntryRejectsOversizedSite) {
  Result res = vault_.CreateEntry(Field(kMaxSiteLen + 1), "user@google.com", MakePW("password"));

  EXPECT_EQ(res, Result::kFailure);
  EXPECT_EQ(vault_.GetEntryCount(), 0);
  EXPECT_NE(vault_.GetLastError().find("Site name exceeds maximum size"), std::string::npos);
}

/**
 * @brief   Verify creating an entry with an oversized account fails
 */
TEST_F(VaultEntryTest, CreateEntryRejectsOversizedAccount) {
  Result res = vault_.CreateEntry("Google", Field(kMaxAccLen + 1), MakePW("password"));

  EXPECT_EQ(res, Result::kFailure);
  EXPECT_EQ(vault_.GetEntryCount(), 0);
  EXPECT_NE(vault_.GetLastError().find("Account exceeds maximum size"), std::string::npos);
}

/**
 * @brief   Verify creating an entry with an empty site name fails
 */
TEST_F(VaultEntryTest, CreateEntryRejectsEmptySite) {
  Result res = vault_.CreateEntry("", "user@google.com", MakePW("password"));

  EXPECT_EQ(res, Result::kFailure);
  EXPECT_EQ(vault_.GetEntryCount(), 0);
  EXPECT_NE(vault_.GetLastError().find("Site name is empty"), std::string::npos);
}

/**
 * @brief   Verify creating an entry with an empty account fails
 */
TEST_F(VaultEntryTest, CreateEntryRejectsEmptyAccount) {
  Result res = vault_.CreateEntry("Google", "", MakePW("password"));

  EXPECT_EQ(res, Result::kFailure);
  EXPECT_EQ(vault_.GetEntryCount(), 0);
  EXPECT_NE(vault_.GetLastError().find("Account is empty"), std::string::npos);
}

/**
 * @brief   Verify creating an entry with an empty password fails
 *
 * The one of the three the validator used to let through. kMinEntrySize counts a byte for every field, and OpenVault
 * sizes its entry-count check on it, so an entry serialized a byte short of that figure is one this build writes and
 * then refuses to read back.
 */
TEST_F(VaultEntryTest, CreateEntryRejectsEmptyPassword) {
  Password empty;

  Result res = vault_.CreateEntry("Google", "user@google.com", empty);

  EXPECT_EQ(res, Result::kFailure);
  EXPECT_EQ(vault_.GetEntryCount(), 0);
  EXPECT_NE(vault_.GetLastError().find("Password is empty"), std::string::npos);
}

/**
 * @brief   Verify updating an entry to an oversized site name fails
 */
TEST_F(VaultEntryTest, UpdateEntryRejectsOversizedSite) {
  vault_.CreateEntry("Google", "user@google.com", MakePW("password"));

  UpdateResult res =
      vault_.UpdateEntry("Google", "user@google.com", Field(kMaxSiteLen + 1), "user@google.com", MakePW("asdf1234"));

  EXPECT_EQ(res, UpdateResult::kError);
  EXPECT_NE(vault_.GetLastError().find("Site name exceeds maximum size"), std::string::npos);

  /* The original entry is untouched, since the fields are checked before anything is built */

  EXPECT_EQ(vault_.GetEntryCount(), 1);

  Password got;

  EXPECT_TRUE(vault_.GetEntryPW("Google", "user@google.com", got));
  EXPECT_TRUE(got.Equal(MakePW("password")));
}

/**
 * @brief   Verify updating an entry to an empty password fails and leaves the original intact
 *
 * The password is read back as well as the two key fields, since an update that got as far as rebuilding the image
 * before refusing would leave the site and the account reading correctly over whatever the offsets now land on.
 */
TEST_F(VaultEntryTest, UpdateEntryRejectsEmptyPassword) {
  vault_.CreateEntry("Google", "user@google.com", MakePW("password"));

  Password empty;

  UpdateResult res = vault_.UpdateEntry("Google", "user@google.com", "Google", "user@google.com", empty);

  EXPECT_EQ(res, UpdateResult::kError);
  EXPECT_NE(vault_.GetLastError().find("Password is empty"), std::string::npos);

  /* The original entry is untouched, since the fields are checked before anything is built */

  EXPECT_EQ(vault_.GetEntryCount(), 1);

  Password got;

  EXPECT_TRUE(vault_.GetEntryPW("Google", "user@google.com", got));
  EXPECT_TRUE(got.Equal(MakePW("password")));

  const auto& entries = vault_.GetEntries();

  EXPECT_NE(entries.find({ .site = "Google", .acc = "user@google.com" }), entries.end());
}

/**
 * @brief   Verify fields of exactly the maximum length are accepted
 *
 * The ceilings are inclusive on the way out, as Entry::Deserialize reads them on the way back in, so a validator one
 * byte too strict would refuse entries the format holds perfectly well.
 */
TEST_F(VaultEntryTest, CreateEntryAcceptsMaxFieldLengths) {
  Password pw;

  ASSERT_EQ(pw.SetData(Field(kMaxEntryPwLen).c_str(), static_cast<size_t>(kMaxEntryPwLen)), Result::kSuccess);

  Result res = vault_.CreateEntry(Field(kMaxSiteLen), Field(kMaxAccLen), pw);

  EXPECT_EQ(res, Result::kSuccess);
  EXPECT_EQ(vault_.GetEntryCount(), 1);
}

/**
 * @brief   Verify a rejected create leaves the vault whole and saveable
 *
 * A refusal is only worth as much as the state it leaves behind. The image and the entry set are rebuilt together on
 * every create, so a check placed after either had been touched would leave the two disagreeing: the count would
 * still read right, and the damage would surface later as a vault that no longer saves or no longer reopens. Reading
 * the entries back off disk after the refusal is what says the rejection cost the vault nothing.
 */
TEST_F(VaultEntryTest, VaultRemainsUsableAfterRejectedCreate) {
  ASSERT_EQ(vault_.NewVault(path_, MakePW("master")), Result::kSuccess);
  ASSERT_EQ(vault_.CreateEntry("Google", "user@google.com", MakePW("s3cr3t!!")), Result::kSuccess);

  const int before = vault_.GetEntryCount();

  EXPECT_EQ(vault_.CreateEntry(Field(kMaxSiteLen + 1), "user@google.com", MakePW("password")), Result::kFailure);
  EXPECT_EQ(vault_.GetEntryCount(), before);

  /* The image still matches the entry set, so it still encrypts and writes */

  ASSERT_EQ(vault_.SaveVault(path_), Result::kSuccess);

  vault_.CloseVault();

  ASSERT_EQ(vault_.OpenVault(path_, MakePW("master")), Result::kSuccess);
  EXPECT_EQ(vault_.GetEntryCount(), before);

  Password got;

  EXPECT_TRUE(vault_.GetEntryPW("Google", "user@google.com", got));
  EXPECT_TRUE(got.Equal(MakePW("s3cr3t!!")));
}

/**
 * @brief   Verify a failed create leaves every observable part of the session unchanged
 *
 * CreateEntry used to install the rebuilt image and entry set and only then check them, so a refusal reached after
 * that point returned kFailure over a session that had already been changed and had no way back. The image and the
 * set are now built aside and installed together in one step, which makes the claim a refusal makes - that nothing
 * happened - something a test can hold it to by reading everything back.
 *
 * Each of the three refusals leaves by a different exit, and the save at the end is what says the image and the set
 * still describe each other rather than merely looking unchanged from the outside.
 */
TEST_F(VaultEntryTest, CreateEntryFailureLeavesSessionIntact) {
  ASSERT_EQ(vault_.NewVault(path_, MakePW("master")), Result::kSuccess);
  ASSERT_EQ(vault_.CreateEntry("Google", "user1@google.com", MakePW("password")), Result::kSuccess);
  ASSERT_EQ(vault_.CreateEntry("Microsoft", "user2@microsoft.com", MakePW("asdf1234")), Result::kSuccess);
  ASSERT_EQ(vault_.CreateEntry("Amazon", "user3@microsoft.com", MakePW("qwerty")), Result::kSuccess);

  const std::vector<EntryView> before = Snapshot();

  ASSERT_EQ(before.size(), 3U);

  /* Field out of range */

  EXPECT_EQ(vault_.CreateEntry(Field(kMaxSiteLen + 1), "user4@google.com", MakePW("password")), Result::kFailure);
  EXPECT_EQ(vault_.GetEntryCount(), 3);
  EXPECT_EQ(Snapshot(), before);

  /* Collides with an entry already held */

  EXPECT_EQ(vault_.CreateEntry("Google", "user1@google.com", MakePW("password")), Result::kFailure);
  EXPECT_EQ(vault_.GetEntryCount(), 3);
  EXPECT_EQ(Snapshot(), before);

  /* Field empty */

  EXPECT_EQ(vault_.CreateEntry("Apple", "", MakePW("password")), Result::kFailure);
  EXPECT_EQ(vault_.GetEntryCount(), 3);
  EXPECT_EQ(Snapshot(), before);

  /* The session is still saveable, and what comes back off the disk is what was there before the refusals */

  ASSERT_EQ(vault_.SaveVault(path_), Result::kSuccess);

  vault_.CloseVault();

  ASSERT_EQ(vault_.OpenVault(path_, MakePW("master")), Result::kSuccess);
  EXPECT_EQ(vault_.GetEntryCount(), 3);
  EXPECT_EQ(Snapshot(), before);
}

/**
 * @brief   Verify a failed update leaves every observable part of the session unchanged
 *
 * The same property as CreateEntryFailureLeavesSessionIntact, over the path that had the most to lose: UpdateEntry
 * erased the old entry and inserted the new one into the live set before anything was checked, so a refusal after
 * that point left the vault holding neither the old entry nor a usable new one.
 */
TEST_F(VaultEntryTest, UpdateEntryFailureLeavesSessionIntact) {
  ASSERT_EQ(vault_.NewVault(path_, MakePW("master")), Result::kSuccess);
  ASSERT_EQ(vault_.CreateEntry("Google", "user1@google.com", MakePW("password")), Result::kSuccess);
  ASSERT_EQ(vault_.CreateEntry("Microsoft", "user2@microsoft.com", MakePW("asdf1234")), Result::kSuccess);
  ASSERT_EQ(vault_.CreateEntry("Amazon", "user3@microsoft.com", MakePW("qwerty")), Result::kSuccess);

  const std::vector<EntryView> before = Snapshot();

  ASSERT_EQ(before.size(), 3U);

  /* Field out of range */

  EXPECT_EQ(
      vault_.UpdateEntry("Google", "user1@google.com", Field(kMaxSiteLen + 1), "user1@google.com", MakePW("newpass")),
      UpdateResult::kError);
  EXPECT_EQ(vault_.GetEntryCount(), 3);
  EXPECT_EQ(Snapshot(), before);

  /* Collides with a different entry */

  EXPECT_EQ(vault_.UpdateEntry("Google", "user1@google.com", "Amazon", "user3@microsoft.com", MakePW("newpass")),
            UpdateResult::kDuplicate);
  EXPECT_EQ(vault_.GetEntryCount(), 3);
  EXPECT_EQ(Snapshot(), before);

  /* Original is not there */

  EXPECT_EQ(vault_.UpdateEntry("Apple", "user4@apple.com", "Apple", "user5@apple.com", MakePW("newpass")),
            UpdateResult::kNotFound);
  EXPECT_EQ(vault_.GetEntryCount(), 3);
  EXPECT_EQ(Snapshot(), before);

  /* The session is still saveable, and what comes back off the disk is what was there before the refusals */

  ASSERT_EQ(vault_.SaveVault(path_), Result::kSuccess);

  vault_.CloseVault();

  ASSERT_EQ(vault_.OpenVault(path_, MakePW("master")), Result::kSuccess);
  EXPECT_EQ(vault_.GetEntryCount(), 3);
  EXPECT_EQ(Snapshot(), before);
}

/* ==================================================
 * Update Entry Test
 * ================================================== */

/**
 * @brief   Verify updating an existing entry succeeds
 */
TEST_F(VaultEntryTest, UpdateBasic) {
  vault_.CreateEntry("Google", "old@google.com", MakePW("password"));

  UpdateResult res = vault_.UpdateEntry("Google", "old@google.com", "Google", "new@google.com", MakePW("asdf1234"));

  EXPECT_EQ(res, UpdateResult::kSuccess);
  EXPECT_EQ(vault_.GetEntryCount(), 1);

  const auto& entries = vault_.GetEntries();
  Entry target = { .site = "Google", .acc = "new@google.com" };

  EXPECT_NE(entries.find(target), entries.end());
}

/**
 * @brief   Verify updating a non-existent entry fails
 */
TEST_F(VaultEntryTest, UpdateNonExistent) {
  UpdateResult res = vault_.UpdateEntry("Google", "user@google.com", "Google", "user@google.com", MakePW("password"));

  EXPECT_EQ(res, UpdateResult::kNotFound);
}

/**
 * @brief   Verify updating to a conflicting entry fails
 */
TEST_F(VaultEntryTest, UpdateConflict) {
  vault_.CreateEntry("Google", "user1@google.com", MakePW("password"));
  vault_.CreateEntry("Google", "user2@google.com", MakePW("asdf1234"));

  UpdateResult res = vault_.UpdateEntry("Google", "user1@google.com", "Google", "user2@google.com", MakePW("qwerty"));

  EXPECT_EQ(res, UpdateResult::kDuplicate);
  EXPECT_EQ(vault_.GetEntryCount(), 2);
}

/**
 * @brief   Verify updating entry to same key with different password succeeds
 */
TEST_F(VaultEntryTest, UpdateSameKeySelf) {
  vault_.CreateEntry("Google", "user@google.com", MakePW("password"));

  UpdateResult res = vault_.UpdateEntry("Google", "user@google.com", "Google", "user@google.com", MakePW("asdf1234"));

  EXPECT_EQ(res, UpdateResult::kSuccess);
  EXPECT_EQ(vault_.GetEntryCount(), 1);

  Password got;

  EXPECT_TRUE(vault_.GetEntryPW("Google", "user@google.com", got));
  EXPECT_TRUE(got.Equal(MakePW("asdf1234")));
}

/* ==================================================
 * Delete Entry Test
 * ================================================== */

/**
 * @brief   Verify deleting an existing entry succeeds
 */
TEST_F(VaultEntryTest, DeleteBasic) {
  vault_.CreateEntry("Google", "user@google.com", MakePW("password"));

  Result res = vault_.DeleteEntry("Google", "user@google.com");

  EXPECT_EQ(res, Result::kSuccess);
  EXPECT_EQ(vault_.GetEntryCount(), 0);
}

/**
 * @brief   Verify deleting a non-existent entry fails
 */
TEST_F(VaultEntryTest, DeleteNonExistent) {
  Result res = vault_.DeleteEntry("Google", "user@google.com");

  EXPECT_EQ(res, Result::kFailure);
}

/**
 * @brief   Verify deleting one entry preserves the passwords of the others
 */
TEST_F(VaultEntryTest, DeletePreservesOthers) {
  vault_.CreateEntry("Google", "user1@google.com", MakePW("password"));
  vault_.CreateEntry("Microsoft", "user2@microsoft.com", MakePW("asdf1234"));
  vault_.CreateEntry("Amazon", "user3@microsoft.com", MakePW("qwerty"));

  vault_.DeleteEntry("Amazon", "user3@microsoft.com");

  EXPECT_EQ(vault_.GetEntryCount(), 2);

  Password google;
  Password microsoft;

  EXPECT_TRUE(vault_.GetEntryPW("Google", "user1@google.com", google));
  EXPECT_TRUE(google.Equal(MakePW("password")));
  EXPECT_TRUE(vault_.GetEntryPW("Microsoft", "user2@microsoft.com", microsoft));
  EXPECT_TRUE(microsoft.Equal(MakePW("asdf1234")));
}

/* ==================================================
 * Accessor Test
 * ================================================== */

/**
 * @brief   Verify getEntries returns correct data in order
 */
TEST_F(VaultEntryTest, GetEntries) {
  vault_.CreateEntry("Google", "user1@google.com", MakePW("password"));
  vault_.CreateEntry("Microsoft", "user2@microsoft.com", MakePW("asdf1234"));
  vault_.CreateEntry("Amazon", "user3@amazon.com", MakePW("qwerty"));

  const auto& entries = vault_.GetEntries();

  EXPECT_EQ(entries.size(), 3);

  auto it = entries.begin();

  EXPECT_EQ(it->site, "Amazon");
  EXPECT_EQ(it->acc, "user3@amazon.com");

  ++it;

  EXPECT_EQ(it->site, "Google");
  EXPECT_EQ(it->acc, "user1@google.com");

  ++it;

  EXPECT_EQ(it->site, "Microsoft");
  EXPECT_EQ(it->acc, "user2@microsoft.com");
}

/**
 * @brief   Verify getEntryCount returns correct count
 */
TEST_F(VaultEntryTest, GetEntryCount) {
  EXPECT_EQ(vault_.GetEntryCount(), 0);

  vault_.CreateEntry("Google", "user1@google.com", MakePW("password"));

  EXPECT_EQ(vault_.GetEntryCount(), 1);

  vault_.CreateEntry("Microsoft", "user2@microsoft.com", MakePW("asdf1234"));

  EXPECT_EQ(vault_.GetEntryCount(), 2);

  vault_.DeleteEntry("Google", "user1@google.com");

  EXPECT_EQ(vault_.GetEntryCount(), 1);
}

/**
 * @brief   Verify getEntryPW fails for a missing entry
 */
TEST_F(VaultEntryTest, GetEntryPWMissing) {
  Password got;

  EXPECT_FALSE(vault_.GetEntryPW("Google", "user@google.com", got));
}

/* ==================================================
 * Unsaved Change Test
 * ================================================== */

/**
 * @brief   Verify each kind of edit marks the vault dirty, starting each time from a saved vault
 *
 * The flag is what stands between an edit and a close that silently drops it, so every operation that rebuilds the
 * image has to raise it on its own. Saving between the steps puts the vault back to clean first, so a later step
 * cannot pass on the strength of an earlier one.
 */
TEST_F(VaultEntryTest, EveryEditMarksVaultDirty) {
  ASSERT_EQ(vault_.NewVault(path_, MakePW("master")), Result::kSuccess);
  EXPECT_FALSE(vault_.IsDirty());

  ASSERT_EQ(vault_.CreateEntry("Google", "user@google.com", MakePW("password")), Result::kSuccess);
  EXPECT_TRUE(vault_.IsDirty());

  ASSERT_EQ(vault_.SaveVault(path_), Result::kSuccess);
  ASSERT_FALSE(vault_.IsDirty());

  ASSERT_EQ(vault_.UpdateEntry("Google", "user@google.com", "Google", "user@google.com", MakePW("changed")),
            UpdateResult::kSuccess);
  EXPECT_TRUE(vault_.IsDirty());

  ASSERT_EQ(vault_.SaveVault(path_), Result::kSuccess);
  ASSERT_FALSE(vault_.IsDirty());

  ASSERT_EQ(vault_.DeleteEntry("Google", "user@google.com"), Result::kSuccess);
  EXPECT_TRUE(vault_.IsDirty());
}

/**
 * @brief   Verify a refused edit leaves a saved vault clean
 *
 * A refusal installs nothing, so it has nothing to lose on close. Marking the vault dirty anyway would put a save
 * prompt in front of a user who has changed nothing, and a prompt that is usually wrong is one people learn to click
 * through.
 */
TEST_F(VaultEntryTest, RejectedEditLeavesVaultClean) {
  ASSERT_EQ(vault_.NewVault(path_, MakePW("master")), Result::kSuccess);
  ASSERT_EQ(vault_.CreateEntry("Google", "user@google.com", MakePW("password")), Result::kSuccess);
  ASSERT_EQ(vault_.CreateEntry("Microsoft", "user@microsoft.com", MakePW("asdf1234")), Result::kSuccess);
  ASSERT_EQ(vault_.SaveVault(path_), Result::kSuccess);
  ASSERT_FALSE(vault_.IsDirty());

  EXPECT_EQ(vault_.CreateEntry("Google", "user@google.com", MakePW("password")), Result::kFailure);
  EXPECT_EQ(vault_.CreateEntry(Field(kMaxSiteLen + 1), "user@google.com", MakePW("password")), Result::kFailure);
  EXPECT_EQ(vault_.UpdateEntry("Amazon", "user@amazon.com", "Amazon", "user@amazon.com", MakePW("qwerty")),
            UpdateResult::kNotFound);
  EXPECT_EQ(vault_.UpdateEntry("Google", "user@google.com", "Microsoft", "user@microsoft.com", MakePW("qwerty")),
            UpdateResult::kDuplicate);
  EXPECT_EQ(vault_.DeleteEntry("Amazon", "user@amazon.com"), Result::kFailure);

  EXPECT_FALSE(vault_.IsDirty());
}

/**
 * @brief   Verify closing the vault leaves nothing marked unsaved
 *
 * Close is where the unsaved changes are dropped, whether saved first or discarded, so a flag that survived it would
 * prompt about a vault that is no longer there.
 */
TEST_F(VaultEntryTest, CloseVaultClearsDirty) {
  ASSERT_EQ(vault_.CreateEntry("Google", "user@google.com", MakePW("password")), Result::kSuccess);
  ASSERT_TRUE(vault_.IsDirty());

  vault_.CloseVault();

  EXPECT_FALSE(vault_.IsDirty());
}

/* ==================================================
 * Close Vault Test
 * ================================================== */

/**
 * @brief   Verify closeVault clears all entries and the session
 */
TEST_F(VaultEntryTest, CloseVault) {
  vault_.CreateEntry("Google", "user1@google.com", MakePW("password"));
  vault_.CreateEntry("Microsoft", "user2@microsoft.com", MakePW("asdf1234"));

  vault_.CloseVault();

  EXPECT_EQ(vault_.GetEntryCount(), 0);
  EXPECT_FALSE(vault_.VerifyPW(MakePW("password")));
}
