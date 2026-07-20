/**
 * @file    entry_test.cpp
 * @brief   Unit tests for Entry struct
 * @author  Astatine387
 */

#include "core/entry.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <set>
#include <string>
#include <vector>

namespace {

/* Reinterpret a C-string as a password source buffer */

const uint8_t* PwBytes(const char* pw) {
  return reinterpret_cast<const uint8_t*>(pw);
}

}  // namespace

/* ==================================================
 * Size Calculation Test
 * ================================================== */

/**
 * @brief   Verify size calculation for a typical entry
 */
TEST(EntryTest, SizeCalculation) {
  Entry entry;

  const char* site = "Google";
  const char* acc = "user@google.com";
  const char* pw = "password";

  entry.site = site;
  entry.acc = acc;
  entry.pw_len = static_cast<uint32_t>(strlen(pw));

  size_t expected = sizeof(uint32_t) + strlen(site) + sizeof(uint32_t) + strlen(acc) + sizeof(uint32_t) + strlen(pw);

  EXPECT_EQ(entry.Size(), expected);
}

/**
 * @brief   Verify size calculation for entry with empty fields
 */
TEST(EntryTest, SizeEmpty) {
  Entry entry;

  size_t expected = sizeof(uint32_t) * 3;

  EXPECT_EQ(entry.Size(), expected);
}

/* ==================================================
 * EntryCmp Test
 * ================================================== */

/**
 * @brief   Verify EntryCmp orders by site first, then by account
 */
TEST(EntryTest, ComparatorOrdering) {
  EntryCmp cmp;

  Entry a = { .site = "Amazon", .acc = "user0" };
  Entry b = { .site = "Amazon", .acc = "user1" };
  Entry c = { .site = "Google", .acc = "user0" };

  EXPECT_TRUE(cmp(a, b));
  EXPECT_FALSE(cmp(b, a));
  EXPECT_TRUE(cmp(a, c));
  EXPECT_FALSE(cmp(c, a));
  EXPECT_TRUE(cmp(b, c));
  EXPECT_FALSE(cmp(c, b));
}

/**
 * @brief   Verify EntryCmp returns false for equal entries
 */
TEST(EntryTest, ComparatorEqual) {
  EntryCmp cmp;

  Entry a = { .site = "Google", .acc = "user" };
  Entry b = { .site = "Google", .acc = "user" };

  EXPECT_FALSE(cmp(a, b));
  EXPECT_FALSE(cmp(b, a));
}

/**
 * @brief   Verify entries are stored without duplication in std::set with EntryCmp
 */
TEST(EntryTest, SetInsertion) {
  std::set<Entry, EntryCmp> entry_set;

  Entry entry0 = { .site = "Google", .acc = "user1" };
  Entry entry1 = { .site = "Google", .acc = "user2" };
  Entry entry2 = { .site = "Amazon", .acc = "user1" };
  Entry entry3 = { .site = "Google", .acc = "user1" };  // Duplicate

  entry_set.insert(entry0);
  entry_set.insert(entry1);
  entry_set.insert(entry2);
  entry_set.insert(entry3);

  EXPECT_EQ(entry_set.size(), 3);
}

/* ==================================================
 * Serialization and Deserialization Test
 * ================================================== */

/**
 * @brief   Verify serialization writes the expected number of bytes
 */
TEST(EntryTest, SerializeSize) {
  Entry entry;

  const char* pw = "password";

  entry.site = "Google";
  entry.acc = "user@google.com";
  entry.pw_len = static_cast<uint32_t>(strlen(pw));

  std::vector<uint8_t> vec(entry.Size());

  size_t size = entry.Serialize(vec.data(), PwBytes(pw));

  EXPECT_EQ(size, entry.Size());
}

/**
 * @brief   Verify round-trip serialization records the password view correctly
 */
TEST(EntryTest, SerializeDeserializeRoundTrip) {
  Entry orig;
  Entry copy;

  const char* pw = "password";

  orig.site = "Google";
  orig.acc = "user@google.com";
  orig.pw_len = static_cast<uint32_t>(strlen(pw));

  std::vector<uint8_t> vec(orig.Size());

  size_t writ = orig.Serialize(vec.data(), PwBytes(pw));
  size_t read = copy.Deserialize(vec.data(), vec.size(), 0);

  EXPECT_EQ(writ, read);
  EXPECT_EQ(copy.site, orig.site);
  EXPECT_EQ(copy.acc, orig.acc);
  EXPECT_EQ(copy.pw_len, orig.pw_len);
  EXPECT_EQ(memcmp(vec.data() + copy.pw_off, pw, copy.pw_len), 0);
}

/**
 * @brief   Verify round-trip with empty fields
 */
TEST(EntryTest, SerializeDeserializeEmpty) {
  Entry orig;
  Entry copy;

  std::vector<uint8_t> vec(orig.Size());

  size_t writ = orig.Serialize(vec.data(), nullptr);
  size_t read = copy.Deserialize(vec.data(), vec.size(), 0);

  EXPECT_EQ(writ, read);
  EXPECT_EQ(copy.site, "");
  EXPECT_EQ(copy.acc, "");
  EXPECT_EQ(copy.pw_len, 0);
}

/**
 * @brief   Verify multiple entries can be serialized sequentially into one buffer
 */
TEST(EntryTest, SerializeMultipleEntries) {
  Entry entry0;
  Entry entry1;

  const char* pw0 = "password";
  const char* pw1 = "asdf1234!";

  entry0.site = "Google";
  entry0.acc = "user@google.com";
  entry0.pw_len = static_cast<uint32_t>(strlen(pw0));

  entry1.site = "Microsoft";
  entry1.acc = "account@microsoft.com";
  entry1.pw_len = static_cast<uint32_t>(strlen(pw1));

  /* Serialize both */

  size_t total_size = entry0.Size() + entry1.Size();
  std::vector<uint8_t> vec(total_size);

  size_t cur = 0;
  cur += entry0.Serialize(vec.data() + cur, PwBytes(pw0));
  cur += entry1.Serialize(vec.data() + cur, PwBytes(pw1));

  EXPECT_EQ(cur, total_size);

  /* Deserialize both */

  Entry copy0;
  Entry copy1;

  cur = 0;
  cur += copy0.Deserialize(vec.data() + cur, vec.size() - cur, cur);
  cur += copy1.Deserialize(vec.data() + cur, vec.size() - cur, cur);

  EXPECT_EQ(cur, total_size);
  EXPECT_EQ(copy0.site, entry0.site);
  EXPECT_EQ(copy0.acc, entry0.acc);
  EXPECT_EQ(copy1.site, entry1.site);
  EXPECT_EQ(copy1.acc, entry1.acc);
  EXPECT_EQ(memcmp(vec.data() + copy0.pw_off, pw0, copy0.pw_len), 0);
  EXPECT_EQ(memcmp(vec.data() + copy1.pw_off, pw1, copy1.pw_len), 0);
}

/**
 * @brief   Verify serialization handles special characters
 */
TEST(EntryTest, SerializeSpecialCharacters) {
  Entry orig;
  Entry copy;

  const char* pw = "p@$$w0rd";

  orig.site = "$i+3n@m3 wi+h $p@c3$ @nd $p3ci@l$";
  orig.acc = "user@google.com";
  orig.pw_len = static_cast<uint32_t>(strlen(pw));

  std::vector<uint8_t> vec(orig.Size());

  orig.Serialize(vec.data(), PwBytes(pw));
  copy.Deserialize(vec.data(), vec.size(), 0);

  EXPECT_EQ(copy.site, orig.site);
  EXPECT_EQ(copy.acc, orig.acc);
  EXPECT_EQ(memcmp(vec.data() + copy.pw_off, pw, copy.pw_len), 0);
}

/* ==================================================
 * Boundary Check Test
 * ================================================== */

/**
 * @brief   Verify deserialization fails when buffer size is insufficient
 */
TEST(EntryTest, DeserializationBoundaryCheck) {
  Entry src;
  Entry dst;

  const char* pw = "password";

  src.site = "Google";
  src.acc = "user@google.com";
  src.pw_len = static_cast<uint32_t>(strlen(pw));

  std::vector<uint8_t> vec(src.Size());

  src.Serialize(vec.data(), PwBytes(pw));

  /* Buffer truncated before site length */

  size_t size = sizeof(uint32_t) - 1;

  EXPECT_EQ(dst.Deserialize(vec.data(), size, 0), 0);

  /* Buffer truncated before site data */

  size = sizeof(uint32_t) + src.site.size() - 1;

  EXPECT_EQ(dst.Deserialize(vec.data(), size, 0), 0);

  /* Buffer truncated before account length */

  size = sizeof(uint32_t) + src.site.size() + sizeof(uint32_t) - 1;

  EXPECT_EQ(dst.Deserialize(vec.data(), size, 0), 0);

  /* Buffer truncated before account data */

  size = sizeof(uint32_t) + src.site.size() + sizeof(uint32_t) + src.acc.size() - 1;

  EXPECT_EQ(dst.Deserialize(vec.data(), size, 0), 0);

  /* Buffer truncated before password length */

  size = sizeof(uint32_t) + src.site.size() + sizeof(uint32_t) + src.acc.size() + sizeof(uint32_t) - 1;

  EXPECT_EQ(dst.Deserialize(vec.data(), size, 0), 0);

  /* Buffer truncated before password data */

  size = sizeof(uint32_t) + src.site.size() + sizeof(uint32_t) + src.acc.size() + sizeof(uint32_t) + src.pw_len - 1;

  EXPECT_EQ(dst.Deserialize(vec.data(), size, 0), 0);
}

/* ==================================================
 * Field Length Validation Test
 * ================================================== */

/**
 * @brief   Build a serialized entry buffer with specified field lengths and deserialize
 * @param   entry       Entry to deserialize into
 * @param   site_len    Site name length
 * @param   acc_len     Account length
 * @param   pw_len      Password length
 * @return  Number of bytes read on success, 0 on failure
 */
static size_t BuildAndDeser(Entry& entry, uint32_t site_len, uint32_t acc_len, uint32_t pw_len) {
  size_t total_size = sizeof(uint32_t) + site_len + sizeof(uint32_t) + acc_len + sizeof(uint32_t) + pw_len;

  std::vector<uint8_t> vec(total_size, 'a');

  size_t cur = 0;

  memcpy(vec.data() + cur, &site_len, sizeof(uint32_t));
  cur += sizeof(uint32_t) + site_len;

  memcpy(vec.data() + cur, &acc_len, sizeof(uint32_t));
  cur += sizeof(uint32_t) + acc_len;

  memcpy(vec.data() + cur, &pw_len, sizeof(uint32_t));

  return entry.Deserialize(vec.data(), vec.size(), 0);
}

/**
 * @brief   Verify deserialization fails when site name exceeds maximum length
 */
TEST(EntryTest, DeserializeOversizedSite) {
  Entry entry;

  EXPECT_EQ(BuildAndDeser(entry, kMaxSiteLen + 1, 1, 1), 0);
}

/**
 * @brief   Verify deserialization fails when account exceeds maximum length
 */
TEST(EntryTest, DeserializeOversizedAccount) {
  Entry entry;

  EXPECT_EQ(BuildAndDeser(entry, 1, kMaxAccLen + 1, 1), 0);
}

/**
 * @brief   Verify deserialization fails when password exceeds maximum length
 */
TEST(EntryTest, DeserializeOversizedPassword) {
  Entry entry;

  EXPECT_EQ(BuildAndDeser(entry, 1, 1, kMaxPWLen + 1), 0);
}

/**
 * @brief   Verify deserialization succeeds at exact maximum field lengths
 */
TEST(EntryTest, DeserializeMaxFieldLengths) {
  Entry entry;

  EXPECT_NE(BuildAndDeser(entry, kMaxSiteLen, kMaxAccLen, kMaxPWLen), 0);
  EXPECT_EQ(entry.site.size(), kMaxSiteLen);
  EXPECT_EQ(entry.acc.size(), kMaxAccLen);
  EXPECT_EQ(entry.pw_len, kMaxPWLen);
}
