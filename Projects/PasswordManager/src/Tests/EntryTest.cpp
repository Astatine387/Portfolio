/**
 * @file    EntryTest.cpp
 * @brief   Unit tests for Entry struct
 * @author  Astatine387
 */

#include <gtest/gtest.h>
#include "Core/Entry.h"


/* ==================================================
 * Size Calculation Test
 * ================================================== */

/**
 * @brief   Verify size calculation for a typical entry
 */
TEST(EntryTest, SizeCalculation) {
    Entry entry;

    const char *site = "Google";
    const char *acc = "user@google.com";
    const char *pw = "password";

    size_t siteLen = strlen(site);
    size_t accLen = strlen(acc);
    size_t pwLen = strlen(pw);

    entry.site = site;
    entry.acc = acc;
    entry.pw.setData(pw, pwLen);

    size_t expected = sizeof(uint32_t) + siteLen + sizeof(uint32_t) + accLen + sizeof(uint32_t) + pwLen;

    EXPECT_EQ(entry.size(), expected);
}

/**
 * @brief   Verify size calculation for entry with empty fields
 */
TEST(EntryTest, SizeEmpty) {
    Entry entry;

    size_t expected = sizeof(uint32_t) * 3;

    EXPECT_EQ(entry.size(), expected);
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

    EXPECT_TRUE(cmp(a, b)); EXPECT_FALSE(cmp(b, a));
    EXPECT_TRUE(cmp(a, c)); EXPECT_FALSE(cmp(c, a));
    EXPECT_TRUE(cmp(b, c)); EXPECT_FALSE(cmp(c, b));
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
    std::set<Entry, EntryCmp> entrySet;
    Password pw;

    pw.setData("password", 8);

    Entry entry0 = { "Google", "user1", pw };
    Entry entry1 = { "Google", "user2", pw };
    Entry entry2 = { "Amazon", "user1", pw };
    Entry entry3 = { "Google", "user1", pw }; // Duplicate

    entrySet.insert(entry0);
    entrySet.insert(entry1);
    entrySet.insert(entry2);
    entrySet.insert(entry3);

    EXPECT_EQ(entrySet.size(), 3);
}


/* ==================================================
 * Serialization and Deserialization Test
 * ================================================== */

/**
 * @brief   Verify serialization writes correct number of bytes
 */
TEST(EntryTest, SerializeSize) {
    Entry entry;

    const char *site = "Google";
    const char *acc = "user@google.com";
    const char *pw = "password";

    size_t siteLen = strlen(site);
    size_t accLen = strlen(acc);
    size_t pwLen = strlen(pw);

    entry.site = site;
    entry.acc = acc;
    entry.pw.setData(pw, pwLen);

    std::vector<uint8_t> vec(entry.size());

    size_t size = entry.ser(vec.data());

    EXPECT_EQ(size, entry.size());
}

/**
 * @brief   Verify round-trip serialization and deserialization preserves data
 */
TEST(EntryTest, SerializeDeserializeRoundTrip) {
    Entry orig, copy;

    const char *site = "Google";
    const char *acc = "user@google.com";
    const char *pw = "password";

    size_t siteLen = strlen(site);
    size_t accLen = strlen(acc);
    size_t pwLen = strlen(pw);

    orig.site = site;
    orig.acc = acc;
    orig.pw.setData(pw, pwLen);

    std::vector<uint8_t> vec(orig.size());

    size_t writ = orig.ser(vec.data());
    size_t read = copy.deser(vec.data(), vec.size());

    EXPECT_EQ(writ, read);
    EXPECT_EQ(copy.site, orig.site);
    EXPECT_EQ(copy.acc, orig.acc);
    EXPECT_EQ(copy.pw.getSize(), orig.pw.getSize());
    EXPECT_TRUE(copy.pw.equal(orig.pw));
}

/**
 * @brief   Verify round-trip with empty fields
 */
TEST(EntryTest, SerializeDeserializeEmpty) {
    Entry orig, copy;

    std::vector<uint8_t> vec(orig.size());

    size_t writ = orig.ser(vec.data());
    size_t read = copy.deser(vec.data(), vec.size());

    EXPECT_EQ(writ, read);
    EXPECT_EQ(copy.site, "");
    EXPECT_EQ(copy.acc, "");
    EXPECT_TRUE(copy.pw.isEmpty());
}

/**
 * @brief   Verify multiple entries can be serialized sequentially into one buffer
 */
TEST(EntryTest, SerializeMultipleEntries) {
    Entry entry0, entry1;

    const char *site0 = "Google", *acc0 = "user@google.com", *pw0 = "password";
    const char *site1 = "Microsoft", *acc1 = "account@microsoft.com", *pw1 = "asdf1234!";

    size_t site0Len = strlen(site0), acc0Len = strlen(acc0), pw0Len = strlen(pw0);
    size_t site1Len = strlen(site1), acc1Len = strlen(acc1), pw1Len = strlen(pw1);

    entry0.site = site0, entry0.acc = acc0, entry0.pw.setData(pw0, pw0Len);
    entry1.site = site1, entry1.acc = acc1, entry1.pw.setData(pw1, pw0Len);


    /* Serialize both */

    size_t cur = 0, totalSize = entry0.size() + entry1.size();

    std::vector<uint8_t> vec(totalSize);

    cur += entry0.ser(vec.data() + cur);
    cur += entry1.ser(vec.data() + cur);

    EXPECT_EQ(cur, totalSize);


    /* Deserialize both */

    Entry copy0, copy1;

    cur = 0;
    cur += copy0.deser(vec.data() + cur, vec.size());
    cur += copy1.deser(vec.data() + cur, vec.size());

    EXPECT_EQ(cur, totalSize);
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

    const char *site = "$i+3n@m3 wi+h $p@c3$ @nd $p3ci@l$";
    const char *acc = "user@google.com";
    const char *pw = "p@$$w0rd";

    size_t siteLen = strlen(site);
    size_t accLen = strlen(acc);
    size_t pwLen = strlen(pw);

    orig.site = site;
    orig.acc = acc;
    orig.pw.setData(pw, pwLen);

    std::vector<uint8_t> vec(orig.size());

    orig.ser(vec.data());
    copy.deser(vec.data(), vec.size());

    EXPECT_EQ(copy.site, orig.site);
    EXPECT_EQ(copy.acc, orig.acc);
    EXPECT_TRUE(copy.pw.equal(orig.pw));
}


/* ==================================================
 * Boundary Check Test
 * ================================================== */

/**
 * @brief   Verify deserialization fails when buffer size is insufficient
 */
TEST(EntryTest, DeserializationBoundaryCheck) {
    Entry src, dst;

    const char *site = "Google";
    const char *acc = "user@google.com";
    const char *pw = "password";

    size_t siteLen = strlen(site);
    size_t accLen = strlen(acc);
    size_t pwLen = strlen(pw);

    src.site = site;
    src.acc = acc;
    src.pw.setData(pw, pwLen);

    std::vector<uint8_t> vec(src.size());

    src.ser(vec.data());


    /* Buffer truncated before site length */

    size_t size = sizeof(uint32_t) - 1;

    EXPECT_EQ(dst.deser(vec.data(), size), 0);


    /* Buffer truncated before site data */

    size = sizeof(uint32_t) + src.site.size() - 1;

    EXPECT_EQ(dst.deser(vec.data(), size), 0);


    /* Buffer truncated before account length */

    size = sizeof(uint32_t) + src.site.size() + sizeof(uint32_t) - 1;

    EXPECT_EQ(dst.deser(vec.data(), size), 0);


    /* Buffer truncated before account data */

    size = sizeof(uint32_t) + src.site.size() + sizeof(uint32_t) + src.acc.size() - 1;

    EXPECT_EQ(dst.deser(vec.data(), size), 0);


    /* Buffer truncated before password length */

    size = sizeof(uint32_t) + src.site.size() + sizeof(uint32_t) + src.acc.size() + sizeof(uint32_t) - 1;

    EXPECT_EQ(dst.deser(vec.data(), size), 0);


    /* Buffer truncated before password length */

    size = sizeof(uint32_t) + src.site.size() + sizeof(uint32_t) + src.acc.size() + sizeof(uint32_t) + src.pw.getSize() - 1;

    EXPECT_EQ(dst.deser(vec.data(), size), 0);
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
static size_t buildAndDeser(Entry &entry, uint32_t siteLen, uint32_t accLen, uint32_t pwLen) {
    size_t totalSize = sizeof(uint32_t) + siteLen + sizeof(uint32_t) + accLen + sizeof(uint32_t) + pwLen;
 
    std::vector<uint8_t> vec(totalSize, 'a');
 
    size_t cur = 0;
 
    memcpy(vec.data() + cur, &siteLen, sizeof(uint32_t));
    cur += sizeof(uint32_t) + siteLen;
 
    memcpy(vec.data() + cur, &accLen, sizeof(uint32_t));
    cur += sizeof(uint32_t) + accLen;
 
    memcpy(vec.data() + cur, &pwLen, sizeof(uint32_t));
 
    return entry.deser(vec.data(), vec.size());
}
 
/**
 * @brief   Verify deserialization fails when site name exceeds maximum length
 */
TEST(EntryTest, DeserializeOversizedSite) {
    Entry entry;
 
    EXPECT_EQ(buildAndDeser(entry, kMaxSiteLen + 1, 1, 1), 0);
}
 
/**
 * @brief   Verify deserialization fails when account exceeds maximum length
 */
TEST(EntryTest, DeserializeOversizedAccount) {
    Entry entry;
 
    EXPECT_EQ(buildAndDeser(entry, 1, kMaxAccLen + 1, 1), 0);
}
 
/**
 * @brief   Verify deserialization fails when password exceeds maximum length
 */
TEST(EntryTest, DeserializeOversizedPassword) {
    Entry entry;
 
    EXPECT_EQ(buildAndDeser(entry, 1, 1, kMaxPWLen + 1), 0);
}
 
/**
 * @brief   Verify deserialization succeeds at exact maximum field lengths
 */
TEST(EntryTest, DeserializeMaxFieldLengths) {
    Entry entry;
 
    EXPECT_NE(buildAndDeser(entry, kMaxSiteLen, kMaxAccLen, kMaxPWLen), 0);
    EXPECT_EQ(entry.site.size(), kMaxSiteLen);
    EXPECT_EQ(entry.acc.size(), kMaxAccLen);
    EXPECT_EQ(entry.pw.getSize(), kMaxPWLen);
}