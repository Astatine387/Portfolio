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
            std::vector<char> vec(size, 'a');

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
 * @brief   Verify FileExists returns false for non-existent file
 */
TEST_F(FileExistsTest, NonExistentFile) {
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
    int size = strlen(pw);

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
    int size0 = strlen(pw0);
    int size1 = strlen(pw1);

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
    int size = strlen(pw);

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
 * GetProcNum Test
 * ================================================== */

/**
 * @brief   Verify GetProcNum returns positive value
 */
TEST(GetProcNumTest, ReturnPositive) {
    int numProcs = GetProcNum();

    EXPECT_GT(numProcs, 0);
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
 * RemoveFile Test
 * ================================================== */

 /**
  * @class   RemoveFileTest
  * @brief   Test class for RemoveFile function
  */
class RemoveFileTest : public ::testing::Test {
protected:
    const char *path = "test.tmp";

    /**
     * @brief   Create a temporary test file
     */
    void createTestFile() {
        FILE *file = nullptr;

        OpenFile(&file, path, "wb");

        if (file) fclose(file);
    }

    /**
     * @brief   Check if file exists
     * @param   path    File path to check
     * @return  true if file exists
     */
    bool fileExists(const char *path) {
        FILE *file = nullptr;

        OpenFile(&file, path, "rb");

        if (file) {
            fclose(file);
            return true;
        }

        return false;
    }

    /**
     * @brief   Clean up temporary files after each test
     */
    void TearDown() override {
        RemoveFile(path);
    }
};

/**
 * @brief   Verify RemoveFile deletes existing file
 */
TEST_F(RemoveFileTest, DeleteExisting) {
    createTestFile();

    ASSERT_TRUE(fileExists(path));

    int res = RemoveFile(path);

    EXPECT_EQ(res, 0);
    EXPECT_FALSE(fileExists(path));
}

/**
 * @brief   Verify RemoveFile fails for non-existent file
 */
TEST_F(RemoveFileTest, DeleteNonExistent) {
    const char *fake = "fake.tmp";

    int res = RemoveFile(fake);

    EXPECT_NE(res, 0);
}


/* ==================================================
 * Seek Test
 * ================================================== */

/**
 * @class   SeekTest
 * @brief   Test class for Seek function
 */
class SeekTest : public::testing::Test {
protected:
    FILE *file = nullptr;
    const char *path = "test.tmp";

    void SetUp() override {
        OpenFile(&file, path, "wb");

        if (file) {
            std::vector<char> data(100, 'a');

            fwrite(data.data(), sizeof(char), 100, file);

            fclose(file);

            file = nullptr;
        }

        OpenFile(&file, path, "rb");
    }

    void TearDown() override {
        if (file) {
            fclose(file);
            file = nullptr;
        }

        RemoveFile(path);
    }
};

/**
 * @brief   Verify Seek moves to beginning of file
 */
TEST_F(SeekTest, SeekToBeginning) {
    EXPECT_EQ(Seek(file, 0, SEEK_SET), 0);
}

/**
 * @brief   Verify Seek moves to end of file
 */
TEST_F(SeekTest, SeekToEnd) {
    EXPECT_EQ(Seek(file, 0, SEEK_END), 0);
}

/**
 * @brief   Verify Seek moves to specific position
 */
TEST_F(SeekTest, SeekToMiddle) {
    EXPECT_EQ(Seek(file, 50, SEEK_SET), 0);
}

/**
 * @brief   Verify Seek with negative offset from end
 */
TEST_F(SeekTest, SeekFromEnd) {
    EXPECT_EQ(Seek(file, -10, SEEK_END), 0);
}


/* ==================================================
 * Wipe Test
 * ================================================== */

/**
 * @brief   Verify Wipe works
 */
TEST(WipeTest, WipeBuffer) {
    uint8_t buff[32];

    memset(buff, 0xFF, 32);

    Wipe(buff, 32);

    for (int i = 0; i < 32; i++) EXPECT_EQ(buff[i], 0);
}

/**
 * @brief   Verify Wipe works with partial buffer
 */
TEST(WipeTest, WipePartial) {
    uint8_t buff[32];

    memset(buff, 0xFF, 32);

    Wipe(buff, 16);  // Only wipe the first half

    for (int i = 0; i < 16; i++) EXPECT_EQ(buff[i], 0);

    for (int i = 16; i < 32; i++) EXPECT_EQ(buff[i], 0xFF);
}