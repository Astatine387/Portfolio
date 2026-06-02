/**
 * @file    utils_test.cpp
 * @brief   Unit tests for utility functions
 * @author  Astatine387
 */

#include <gtest/gtest.h>

#include <string>

#include "Utils/platform.h"

/* ==================================================
 * GetFileSize Test
 * ================================================== */

/**
 * @class   GetFileSizeTest
 * @brief   Test class for GetFileSize function
 */
class GetFileSizeTest : public ::testing::Test {
 protected:
  FILE* file_ = nullptr;
  std::string path_ = "test.tmp";

  /**
   * @brief   Clean up temporary files after each test
   */
  void TearDown() override {
    if (file_) {
      fclose(file_);
      file_ = nullptr;
    }

    RemoveFile(path_);
  }

  /**
   * @brief   Create file with specified size
   * @param   size    File size in bytes
   */
  void Create(size_t size) {
    OpenFile(&file_, path_, "wb+");

    if (file_) {
      std::vector<char> vec(size, 'a');

      if (size > 0) {
        fwrite(vec.data(), 1, size, file_);
      }

      fclose(file_);

      file_ = nullptr;
    }

    OpenFile(&file_, path_, "rb");
  }
};

/**
 * @brief   Verify GetFileSize works with empty file
 */
TEST_F(GetFileSizeTest, EmptyFile) {
  Create(0);

  EXPECT_EQ(GetFileSize(file_), 0);
}

/**
 * @brief   Verify GetFileSize works with an arbitrary sized file
 */
TEST_F(GetFileSizeTest, ArbitSizeFile) {
  Create(1000);

  EXPECT_EQ(GetFileSize(file_), 1000);
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
  std::string path_ = "test_exists.tmp";

  /**
   * @brief   Clean up temporary files after each test
   */
  void TearDown() override { RemoveFile(path_); }

  /**
   * @brief   Create a temporary test file
   */
  void Create() {
    FILE* file = nullptr;

    OpenFile(&file, path_, "wb");

    if (file) {
      fclose(file);
    }
  }
};

/**
 * @brief   Verify FileExists returns true for existing file
 */
TEST_F(FileExistsTest, ExistingFile) {
  Create();

  EXPECT_TRUE(FileExists(path_));
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
  Create();

  ASSERT_TRUE(FileExists(path_));

  RemoveFile(path_);

  EXPECT_FALSE(FileExists(path_));
}

/* ==================================================
 * Argon2id Test
 * ================================================== */

/**
 * @brief   Verify Argon2id derives same key for same input
 */
TEST(Argon2idTest, SameInput) {
  uint8_t salt[kSaltSize], key0[kKeySize], key1[kKeySize];
  const char* pw = "password";
  int size = strlen(pw);

  for (int i = 0; i < kSaltSize; i++) {
    salt[i] = i;
  }

  EXPECT_EQ(Argon2id(salt, pw, size, key0), 0);
  EXPECT_EQ(Argon2id(salt, pw, size, key1), 0);

  EXPECT_EQ(memcmp(key0, key1, kKeySize), 0);
}

/**
 * @brief   Verify different passwords produce different keys
 */
TEST(Argon2idTest, DifferentPW) {
  uint8_t salt[kSaltSize], key0[kKeySize], key1[kKeySize];
  const char* pw0 = "password";
  const char* pw1 = "asdf1234";
  int size0 = strlen(pw0);
  int size1 = strlen(pw1);

  for (int i = 0; i < kSaltSize; i++) {
    salt[i] = i;
  }

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
  const char* pw = "password";
  int size = strlen(pw);

  for (int i = 0; i < kSaltSize; i++) {
    salt0[i] = i;
  }

  for (int i = 0; i < kSaltSize; i++) {
    salt1[i] = i + 16;
  }

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

  for (int i = 0; i < kSaltSize; i++) {
    salt[i] = i;
  }

  EXPECT_EQ(Argon2id(salt, "", 0, key), 0);
}

/* ==================================================
 * OpenFile Test
 * ================================================== */

/**
 * @class   OpenFileTest
 * @brief   Test class for OpenFile function
 */
class OpenFileTest : public ::testing::Test {
 protected:
  FILE* file_ = nullptr;
  std::string path_ = "test.tmp";

  /**
   * @brief   Clean up temporary files after each test
   */

  void TearDown() override {
    if (file_) {
      fclose(file_);
      file_ = nullptr;
    }

    RemoveFile(path_);
  }
};

/**
 * @brief   Verify OpenFile creates new file in write mode
 */
TEST_F(OpenFileTest, CreateNew) {
  OpenFile(&file_, path_, "wb+");

  EXPECT_NE(file_, nullptr);
}

/**
 * @brief   Verify OpenFile returns nullptr for non-existent file in read mode
 */
TEST_F(OpenFileTest, ReadNonExistent) {
  OpenFile(&file_, "fake.tmp", "rb");

  EXPECT_EQ(file_, nullptr);
}

/**
 * @brief   Verify OpenFile opens existing file in read mode
 */
TEST_F(OpenFileTest, OpenExisting) {
  OpenFile(&file_, path_, "wb+");

  fclose(file_);
  file_ = nullptr;

  OpenFile(&file_, path_, "rb");

  EXPECT_NE(file_, nullptr);
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
  bool all_zero = true;

  EXPECT_EQ(Random(buff, 32), 0);

  for (int i = 0; i < 32; i++) {
    if (buff[i]) {
      all_zero = false;
      break;
    }
  }

  EXPECT_FALSE(all_zero);
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
  const char* path_ = "test.tmp";

  /**
   * @brief   Create a temporary test file
   */
  void CreateTestFile() {
    FILE* file = nullptr;

    OpenFile(&file, path_, "wb");

    if (file) {
      fclose(file);
    }
  }

  /**
   * @brief   Check if file exists
   * @param   path    File path to check
   * @return  true if file exists
   */
  bool FileExists(const char* path) {
    FILE* file = nullptr;

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
  void TearDown() override { RemoveFile(path_); }
};

/**
 * @brief   Verify RemoveFile deletes existing file
 */
TEST_F(RemoveFileTest, DeleteExisting) {
  CreateTestFile();

  ASSERT_TRUE(FileExists(path_));

  int res = RemoveFile(path_);

  EXPECT_EQ(res, 0);
  EXPECT_FALSE(FileExists(path_));
}

/**
 * @brief   Verify RemoveFile fails for non-existent file
 */
TEST_F(RemoveFileTest, DeleteNonExistent) {
  const char* fake = "fake.tmp";

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
class SeekTest : public ::testing::Test {
 protected:
  FILE* file_ = nullptr;
  const char* path_ = "test.tmp";

  void SetUp() override {
    OpenFile(&file_, path_, "wb");

    if (file_) {
      std::vector<char> data(100, 'a');

      fwrite(data.data(), sizeof(char), 100, file_);

      fclose(file_);

      file_ = nullptr;
    }

    OpenFile(&file_, path_, "rb");
  }

  void TearDown() override {
    if (file_) {
      fclose(file_);
      file_ = nullptr;
    }

    RemoveFile(path_);
  }
};

/**
 * @brief   Verify Seek moves to beginning of file
 */
TEST_F(SeekTest, SeekToBeginning) {
  EXPECT_EQ(Seek(file_, 0, SEEK_SET), 0);
}

/**
 * @brief   Verify Seek moves to end of file
 */
TEST_F(SeekTest, SeekToEnd) {
  EXPECT_EQ(Seek(file_, 0, SEEK_END), 0);
}

/**
 * @brief   Verify Seek moves to specific position
 */
TEST_F(SeekTest, SeekToMiddle) {
  EXPECT_EQ(Seek(file_, 50, SEEK_SET), 0);
}

/**
 * @brief   Verify Seek with negative offset from end
 */
TEST_F(SeekTest, SeekFromEnd) {
  EXPECT_EQ(Seek(file_, -10, SEEK_END), 0);
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

  for (int i = 0; i < 32; i++) {
    EXPECT_EQ(buff[i], 0);
  }
}

/**
 * @brief   Verify Wipe works with partial buffer
 */
TEST(WipeTest, WipePartial) {
  uint8_t buff[32];

  memset(buff, 0xFF, 32);

  Wipe(buff, 16);  // Only wipe the first half

  for (int i = 0; i < 16; i++) {
    EXPECT_EQ(buff[i], 0);
  }

  for (int i = 16; i < 32; i++) {
    EXPECT_EQ(buff[i], 0xFF);
  }
}