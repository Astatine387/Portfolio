/**
 * @file    EntryTest.cpp
 * @brief   Unit tests for Entry struct
 * @author  Astatine387
 */

#include "Core/Entry.h"

#include <gtest/gtest.h>

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

  size_t site_len = strlen(site);
  size_t acc_len = strlen(acc);
  size_t pw_len = strlen(pw);

  entry.site = site;
  entry.acc = acc;
  entry.pw.SetData(pw, pw_len);

  size_t expected =
      sizeof(uint32_t) + site_len + sizeof(uint32_t) + acc_len + sizeof(uint32_t) + pw_len;

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

  Entry a = { "Amazon", "user0" };
  Entry b = { "Amazon", "user1" };
  Entry c = { "Google", "user0" };

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

  Entry a = { "Google", "user" };
  Entry b = { "Google", "user" };

  EXPECT_FALSE(cmp(a, b));
  EXPECT_FALSE(cmp(b, a));
}

/**
 * @brief   Verify entries are stored without duplication in std::set with EntryCmp
 */
TEST(EntryTest, SetInsertion) {
  std::set<Entry, EntryCmp> entry_set;
  Password pw;

  pw.SetData("password", 8);

  Entry entry0 = { "Google", "user1", pw };
  Entry entry1 = { "Google", "user2", pw };
  Entry entry2 = { "Amazon", "user1", pw };
  Entry entry3 = { "Google", "user1", pw };  // Duplicate

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
 * @brief   Verify serialization writes correct number of bytes
 */
TEST(EntryTest, SerializeSize) {
  Entry entry;

  const char* site = "Google";
  const char* acc = "user@google.com";
  const char* pw = "password";

  size_t site_len = strlen(site);
  size_t acc_len = strlen(acc);
  size_t pw_len = strlen(pw);

  entry.site = site;
  entry.acc = acc;
  entry.pw.SetData(pw, pw_len);

  std::vector<uint8_t> vec(entry.Size());

  size_t size = entry.Ser(vec.data());

  EXPECT_EQ(size, entry.Size());
}

/**
 * @brief   Verify round-trip serialization and deserialization preserves data
 */
TEST(EntryTest, SerializeDeserializeRoundTrip) {
  Entry orig, copy;

  const char* site = "Google";
  const char* acc = "user@google.com";
  const char* pw = "password";

  size_t site_len = strlen(site);
  size_t acc_len = strlen(acc);
  size_t pw_len = strlen(pw);

  orig.site = site;
  orig.acc = acc;
  orig.pw.SetData(pw, pw_len);

  std::vector<uint8_t> vec(orig.Size());

  size_t writ = orig.Ser(vec.data());
  size_t read = copy.Deser(vec.data(), vec.size());

  EXPECT_EQ(writ, read);
  EXPECT_EQ(copy.site, orig.site);
  EXPECT_EQ(copy.acc, orig.acc);
  EXPECT_EQ(copy.pw.GetSize(), orig.pw.GetSize());
  EXPECT_TRUE(copy.pw.Equal(orig.pw));
}

/**
 * @brief   Verify round-trip with empty fields
 */
TEST(EntryTest, SerializeDeserializeEmpty) {
  Entry orig, copy;

  std::vector<uint8_t> vec(orig.Size());

  size_t writ = orig.Ser(vec.data());
  size_t read = copy.Deser(vec.data(), vec.size());

  EXPECT_EQ(writ, read);
  EXPECT_EQ(copy.site, "");
  EXPECT_EQ(copy.acc, "");
  EXPECT_TRUE(copy.pw.IsEmpty());
}

/**
 * @brief   Verify multiple entries can be serialized sequentially into one buffer
 */
TEST(EntryTest, SerializeMultipleEntries) {
  Entry entry0, entry1;

  const char *site0 = "Google", *acc0 = "user@google.com", *pw0 = "password";
  const char *site1 = "Microsoft", *acc1 = "account@microsoft.com", *pw1 = "asdf1234!";

  size_t site0_len = strlen(site0), acc0_len = strlen(acc0), pw0_len = strlen(pw0);
  size_t site1_len = strlen(site1), acc1_len = strlen(acc1), pw1_len = strlen(pw1);

  entry0.site = site0, entry0.acc = acc0, entry0.pw.SetData(pw0, pw0_len);
  entry1.site = site1, entry1.acc = acc1, entry1.pw.SetData(pw1, pw0_len);

  /* Serialize both */

  size_t cur = 0, total_size = entry0.Size() + entry1.Size();

  std::vector<uint8_t> vec(total_size);

  cur += entry0.Ser(vec.data() + cur);
  cur += entry1.Ser(vec.data() + cur);

  EXPECT_EQ(cur, total_size);

  /* Deserialize both */

  Entry copy0, copy1;

  cur = 0;
  cur += copy0.Deser(vec.data() + cur, vec.size());
  cur += copy1.Deser(vec.data() + cur, vec.size());

  EXPECT_EQ(cur, total_size);
  EXPECT_EQ(copy0.site, site0);
  EXPECT_EQ(copy0.acc, acc0);
  EXPECT_EQ(copy1.site, site1);
  EXPECT_EQ(copy1.acc, acc1);
}

/**
 * @brief   Verify serialization handles special characters
 */
TEST(EntryTest, SerializeSpecialCharacters) {
  Entry orig, copy;

  const char* site = "$i+3n@m3 wi+h $p@c3$ @nd $p3ci@l$";
  const char* acc = "user@google.com";
  const char* pw = "p@$$w0rd";

  size_t site_len = strlen(site);
  size_t acc_len = strlen(acc);
  size_t pw_len = strlen(pw);

  orig.site = site;
  orig.acc = acc;
  orig.pw.SetData(pw, pw_len);

  std::vector<uint8_t> vec(orig.Size());

  orig.Ser(vec.data());
  copy.Deser(vec.data(), vec.size());

  EXPECT_EQ(copy.site, orig.site);
  EXPECT_EQ(copy.acc, orig.acc);
  EXPECT_TRUE(copy.pw.Equal(orig.pw));
}

/* ==================================================
 * Boundary Check Test
 * ================================================== */

/**
 * @brief   Verify deserialization fails when buffer size is insufficient
 */
TEST(EntryTest, DeserializationBoundaryCheck) {
  Entry src, dst;

  const char* site = "Google";
  const char* acc = "user@google.com";
  const char* pw = "password";

  size_t site_len = strlen(site);
  size_t acc_len = strlen(acc);
  size_t pw_len = strlen(pw);

  src.site = site;
  src.acc = acc;
  src.pw.SetData(pw, pw_len);

  std::vector<uint8_t> vec(src.Size());

  src.Ser(vec.data());

  /* Buffer truncated before site length */

  size_t size = sizeof(uint32_t) - 1;

  EXPECT_EQ(dst.Deser(vec.data(), size), 0);

  /* Buffer truncated before site data */

  size = sizeof(uint32_t) + src.site.size() - 1;

  EXPECT_EQ(dst.Deser(vec.data(), size), 0);

  /* Buffer truncated before account length */

  size = sizeof(uint32_t) + src.site.size() + sizeof(uint32_t) - 1;

  EXPECT_EQ(dst.Deser(vec.data(), size), 0);

  /* Buffer truncated before account data */

  size = sizeof(uint32_t) + src.site.size() + sizeof(uint32_t) + src.acc.size() - 1;

  EXPECT_EQ(dst.Deser(vec.data(), size), 0);

  /* Buffer truncated before password length */

  size =
      sizeof(uint32_t) + src.site.size() + sizeof(uint32_t) + src.acc.size() + sizeof(uint32_t) - 1;

  EXPECT_EQ(dst.Deser(vec.data(), size), 0);

  /* Buffer truncated before password length */

  size = sizeof(uint32_t) + src.site.size() + sizeof(uint32_t) + src.acc.size() + sizeof(uint32_t) +
         src.pw.GetSize() - 1;

  EXPECT_EQ(dst.Deser(vec.data(), size), 0);
}

/* ==================================================
 * Field Length Validation Test
 * ================================================== */

/**
 * @brief   Build a serialized entry buffer with specified field lengths and deserialize
 * @param   entry       Entry to deserialize into
 * @param   siteLen     Site name length
 * @param   accLen      Account length
 * @param   pwLen       Password length
 * @return  Number of bytes read on success, 0 on failure
 */
static size_t BuildAndDeser(Entry& entry, uint32_t site_len, uint32_t acc_len, uint32_t pw_len) {
  size_t total_size =
      sizeof(uint32_t) + site_len + sizeof(uint32_t) + acc_len + sizeof(uint32_t) + pw_len;

  std::vector<uint8_t> vec(total_size, 'a');

  size_t cur = 0;

  memcpy(vec.data() + cur, &site_len, sizeof(uint32_t));
  cur += sizeof(uint32_t) + site_len;

  memcpy(vec.data() + cur, &acc_len, sizeof(uint32_t));
  cur += sizeof(uint32_t) + acc_len;

  memcpy(vec.data() + cur, &pw_len, sizeof(uint32_t));

  return entry.Deser(vec.data(), vec.size());
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
  EXPECT_EQ(entry.pw.GetSize(), kMaxPWLen);
}