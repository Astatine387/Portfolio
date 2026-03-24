/**
 * @file    UtilsTest.cpp
 * @brief   Unit tests for utility functions
 * @author  Astatine387
 */

#include "Utils/library.h"
#include <QString>
#include <gtest/gtest.h>


/* ==================================================
 * GetFileSize Test
 * ================================================== */

/**
 * @class   GetFileSizeTest
 * @brief   Test class for GetFileSize function
 */
class GetFileSizeTest : public::testing::Test {
protected:
    FILE *file = nullptr;
    QString path = "test.tmp";

    /**
     * @brief   Clean up temporary files after each test
     */
    void TearDown() override {
        if (file) {
            fclose(file);
            file = nullptr;
        }

        RemoveFile(path);
    }

    /**
     * @brief   Create file with specified size
     * @param   size    File size in bytes
     */
    void create(size_t size) {
        OpenFile(&file, path, "wb+");

        if (file) {
            std::vector<uint8_t> vec(size, 0x00);

            fwrite(vec.data(), 1, size, file);

            fclose(file);

            file = nullptr;
        }

        OpenFile(&file, path, "rb");
    }
};

/**
 * @brief   Verify GetFileSize works with empty file
 */
TEST_F(GetFileSizeTest, EmptyFile) {
    create(0);

    EXPECT_EQ(GetFileSize(file), 0);
}

/**
 * @brief   Verify GetFileSize works with an arbitrary sized file
 */
TEST_F(GetFileSizeTest, ArbitSizeFile) {
    create(1000);

    EXPECT_EQ(GetFileSize(file), 1000);
}


/* ==================================================
 * FileExists Test
 * ================================================== */

/**
 * @class   FileExistsTest
 * @brief   Test class for FileExists function
 */
class FileExistsTest : public ::testing::Test {
protected:
    QString path = "test_exists.tmp";

    /**
     * @brief   Clean up temporary files after each test
     */
    void TearDown() override {
        RemoveFile(path);
    }

    /**
     * @brief   Create a temporary test file
     */
    void create() {
        FILE *file = nullptr;

        OpenFile(&file, path, "wb");

        if (file) fclose(file);
    }
};

/**
 * @brief   Verify FileExists returns true for existing file
 */
TEST_F(FileExistsTest, ExistingFile) {
    create();

    EXPECT_TRUE(FileExists(path));
}

/**
 * @brief   Verify FileExists returns false for non-existing file
 */
TEST_F(FileExistsTest, NonExistingFile) {
    EXPECT_FALSE(FileExists("fake.tmp"));
}

/**
 * @brief   Verify FileExists returns false after file deletion
 */
TEST_F(FileExistsTest, AfterDeletion) {
    create();

    ASSERT_TRUE(FileExists(path));

    RemoveFile(path);

    EXPECT_FALSE(FileExists(path));
}


/* ==================================================
 * Argon2id Test
 * ================================================== */

/**
 * @brief   Verify Argon2id derives same key for same input
 */
TEST(Argon2idTest, SameInput) {
    uint8_t salt[kSaltSize], key0[kKeySize], key1[kKeySize];
    const char *pw = "password";
    size_t size = strlen(pw);

    for (int i = 0; i < kSaltSize; i++) salt[i] = i;

    EXPECT_EQ(Argon2id(salt, pw, size, key0), 0);
    EXPECT_EQ(Argon2id(salt, pw, size, key1), 0);

    EXPECT_EQ(memcmp(key0, key1, kKeySize), 0);
}

/**
 * @brief   Verify different passwords produce different keys
 */
TEST(Argon2idTest, DifferentPW) {
    uint8_t salt[kSaltSize], key0[kKeySize], key1[kKeySize];
    const char *pw0 = "password";
    const char *pw1 = "asdf1234";
    size_t size0 = strlen(pw0);
    size_t size1 = strlen(pw1);

    for (int i = 0; i < kSaltSize; i++) salt[i] = i;

    Argon2id(salt, pw0, size0, key0);
    Argon2id(salt, pw1, size1, key1);

    EXPECT_NE(memcmp(key0, key1, kKeySize), 0);
}

/**
 * @brief   Verify different salts produce different keys
 */
TEST(Argon2idTest, DifferentSalt) {
    uint8_t salt0[kSaltSize], salt1[kSaltSize];
    uint8_t key0[kKeySize], key1[kKeySize];
    const char *pw = "password";
    size_t size = strlen(pw);

    for (int i = 0; i < kSaltSize; i++) salt0[i] = i;
    for (int i = 0; i < kSaltSize; i++) salt1[i] = i + 16;

    Argon2id(salt0, pw, size, key0);
    Argon2id(salt1, pw, size, key1);

    EXPECT_NE(memcmp(key0, key1, kKeySize), 0);
}

/**
 * @brief   Verify Argon2id works with empty password
 */
TEST(Argon2Test, EmptyPassword) {
    uint8_t salt[kSaltSize];
    uint8_t key[kKeySize];

    for (int i = 0; i < kSaltSize; i++) salt[i] = i;

    EXPECT_EQ(Argon2id(salt, "", 0, key), 0);
}


/* ==================================================
 * OpenFile Test
 * ================================================== */

/**
 * @class   OpenFileTest
 * @brief   Test class for OpenFile function
 */
class OpenFileTest : public::testing::Test {
protected:
    FILE *file = nullptr;
    QString path = "test.tmp";

    /**
     * @brief   Clean up temporary files after each test
     */

    void TearDown() override {
        if (file) {
            fclose(file);
            file = nullptr;
        }

        RemoveFile(path);
    }
};

/**
 * @brief   Verify OpenFile creates new file in write mode
 */
TEST_F(OpenFileTest, CreateNew) {
    OpenFile(&file, path, "wb+");

    EXPECT_NE(file, nullptr);
}

/**
 * @brief   Verify OpenFile returns nullptr for non-existent file in read mode
 */
TEST_F(OpenFileTest, ReadNonExistent) {
    OpenFile(&file, "fake.tmp", "rb");

    EXPECT_EQ(file, nullptr);
}

/**
 * @brief   Verify OpenFile opens existing file in read mode
 */
TEST_F(OpenFileTest, OpenExisting) {
    OpenFile(&file, path, "wb+");

    fclose(file);
    file = nullptr;

    OpenFile(&file, path, "rb");

    EXPECT_NE(file, nullptr);
}


/* ==================================================
 * Random Test
 * ================================================== */

/**
 * @brief   Verify Random generates non-zero data
 *
 * The probability of 32 random bytes being all zero is negligible (2^-256)
 */
TEST(RandomTest, GeneratesNonZero) {
    uint8_t buff[32] = { 0 };
    bool allZero = true;

    EXPECT_EQ(Random(buff, 32), 0);

    for (int i = 0; i < 32; i++) {
        if (buff[i]) {
            allZero = false;
            break;
        }
    }

    EXPECT_FALSE(allZero);
}

/**
 * @brief   Verify Random generates different data each time
 */
TEST(RandomTest, DifferentEachCall) {
    uint8_t buff0[32], buff1[32];

    Random(buff0, 32);
    Random(buff1, 32);

    EXPECT_NE(memcmp(buff0, buff1, 32), 0);
}


/* ==================================================
 * RandomRange Test
 * ================================================== */

/**
 * @brief   Verify RandomRange generates values within the specified range
 */
TEST(RandomRangeTest, WithinRange) {
    for (int i = 0; i < 100; i++) {
        uint32_t val = RandomRange(0, 9);

        EXPECT_GE(val, 0u);
        EXPECT_LE(val, 9u);
    }
}

/**
 * @brief   Verify RandomRange works with min == max
 */
TEST(RandomRangeTest, MinEqualsMax) {
    for (int i = 0; i < 10; i++) {
        uint32_t val = RandomRange(0, 0);
        EXPECT_EQ(val, 0u);
    }
}


/* ==================================================
 * RenameFile Test
 * ================================================== */

/**
 * @brief   Verify renaming a file succeeds
 */
TEST(UtilsTest, RenameFileBasic) {
    QString src = "rename_src.tmp";
    QString dst = "rename_dst.tmp";


    /* Create source file */

    FILE *file = nullptr;

    OpenFile(&file, src, "wb");
    ASSERT_NE(file, nullptr);

    const char *data = "test data";

    fwrite(data, 1, strlen(data), file);
    fclose(file);

    EXPECT_TRUE(FileExists(src));


    /* Rename */

    EXPECT_EQ(RenameFile(src, dst), 0);
    EXPECT_FALSE(FileExists(src));
    EXPECT_TRUE(FileExists(dst));


    /* Cleanup */

    RemoveFile(dst);
}

/**
 * @brief   Verify renaming a non-existent file fails
 */
TEST(UtilsTest, RenameFileNonExistent) {
    EXPECT_NE(RenameFile("nonexistent.tmp", "dst.tmp"), 0);
}

/**
 * @brief   Verify renaming overwrites existing destination file
 */
TEST(UtilsTest, RenameFileOverwrite) {
    QString src = "src.tmp";
    QString dst = "dst.tmp";


    /* Create source file */

    FILE *file = nullptr;

    OpenFile(&file, src, "wb");
    ASSERT_NE(file, nullptr);

    const char *srcData = "Hello, world!";

    fwrite(srcData, 1, strlen(srcData), file);
    fclose(file);


    /* Create destination file with different data */

    OpenFile(&file, dst, "wb");
    ASSERT_NE(file, nullptr);

    const char *dstData = "Goodbye, world!";

    fwrite(dstData, 1, strlen(dstData), file);
    fclose(file);

    EXPECT_TRUE(FileExists(src));
    EXPECT_TRUE(FileExists(dst));


    /* Rename (overwrite) */

    EXPECT_EQ(RenameFile(src, dst), 0);
    EXPECT_FALSE(FileExists(src));
    EXPECT_TRUE(FileExists(dst));


    /* Verify destination contains source data */

    OpenFile(&file, dst, "rb");
    ASSERT_NE(file, nullptr);

    int64_t size = GetFileSize(file);

    EXPECT_EQ(size, static_cast<int64_t>(strlen(srcData)));

    char buff[32] = { 0 };

    fread(buff, 1, size, file);
    fclose(file);

    EXPECT_EQ(memcmp(buff, srcData, strlen(srcData)), 0);


    /* Cleanup */

    RemoveFile(dst);
}



/* ==================================================
 * Wipe Test
 * ================================================== */

/**
 * @brief   Verify Wipe zeroes out entire buffer
 */
TEST(WipeTest, WipeBuffer) {
    uint8_t buff[32];

    memset(buff, 0xFF, 32);

    Wipe(buff, 32);

    for (int i = 0; i < 32; i++) EXPECT_EQ(buff[i], 0);
}

/**
 * @brief   Verify Wipe zeroes only the specified portion
 */
TEST(WipeTest, WipePartial) {
    uint8_t buff[32];

    memset(buff, 0xFF, 32);

    Wipe(buff, 16);

    for (int i = 0; i < 16; i++) EXPECT_EQ(buff[i], 0);

    for (int i = 16; i < 32; i++) EXPECT_EQ(buff[i], 0xFF);
}


/* ==================================================
 * Shuffle Test
 * ================================================== */

/**
 * @brief   Verify Shuffle preserves all elements
 */
TEST(ShuffleTest, PreservesElements) {
    uint8_t arr[10];

    for (int i = 0; i < 10; i++) arr[i] = i;

    Shuffle(arr, 10);


    /* Sort and verify all elements are preserved */

    std::vector<uint8_t> sorted(arr, arr + 10);

    std::sort(sorted.begin(), sorted.end());

    for (int i = 0; i < 10; i++) EXPECT_EQ(sorted[i], i);
}


/* ==================================================
 * Swap Test
 * ================================================== */

/**
 * @brief   Verify Swap exchanges two values
 */
TEST(SwapTest, SwapValues) {
    uint8_t a = 0x11, b = 0x22;

    Swap(&a, &b);

    EXPECT_EQ(a, 0x22);
    EXPECT_EQ(b, 0x11);
}