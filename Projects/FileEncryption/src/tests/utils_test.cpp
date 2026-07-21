/**
 * @file    utils_test.cpp
 * @brief   Unit tests for utility functions
 * @author  Astatine387
 */

#include <gtest/gtest.h>

#include <array>
#include <string>

#include "utils/platform.h"

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
  std::array<uint8_t, kSaltSize> salt;
  std::array<uint8_t, kKeySize> key0;
  std::array<uint8_t, kKeySize> key1;
  const char* pw = "password";
  int size = static_cast<int>(strlen(pw));

  for (size_t i = 0; i < kSaltSize; i++) {
    salt[i] = i;
  }

  EXPECT_EQ(Argon2id(salt.data(), pw, size, key0.data()), Result::kSuccess);
  EXPECT_EQ(Argon2id(salt.data(), pw, size, key1.data()), Result::kSuccess);

  EXPECT_EQ(memcmp(key0.data(), key1.data(), kKeySize), 0);
}

/**
 * @brief   Verify different passwords produce different keys
 */
TEST(Argon2idTest, DifferentPW) {
  std::array<uint8_t, kSaltSize> salt;
  std::array<uint8_t, kKeySize> key0;
  std::array<uint8_t, kKeySize> key1;
  const char* pw0 = "password";
  const char* pw1 = "asdf1234";
  int size0 = static_cast<int>(strlen(pw0));
  int size1 = static_cast<int>(strlen(pw1));

  for (size_t i = 0; i < kSaltSize; i++) {
    salt[i] = i;
  }

  Argon2id(salt.data(), pw0, size0, key0.data());
  Argon2id(salt.data(), pw1, size1, key1.data());

  EXPECT_NE(memcmp(key0.data(), key1.data(), kKeySize), 0);
}

/**
 * @brief   Verify different salts produce different keys
 */
TEST(Argon2idTest, DifferentSalt) {
  std::array<uint8_t, kSaltSize> salt0;
  std::array<uint8_t, kSaltSize> salt1;
  std::array<uint8_t, kKeySize> key0;
  std::array<uint8_t, kKeySize> key1;
  const char* pw = "password";
  int size = static_cast<int>(strlen(pw));

  for (size_t i = 0; i < kSaltSize; i++) {
    salt0[i] = i;
  }

  for (size_t i = 0; i < kSaltSize; i++) {
    salt1[i] = i + 16;
  }

  Argon2id(salt0.data(), pw, size, key0.data());
  Argon2id(salt1.data(), pw, size, key1.data());

  EXPECT_NE(memcmp(key0.data(), key1.data(), kKeySize), 0);
}

/**
 * @brief   Verify Argon2id works with empty password
 */
TEST(Argon2Test, EmptyPassword) {
  std::array<uint8_t, kSaltSize> salt;
  std::array<uint8_t, kKeySize> key;

  for (size_t i = 0; i < kSaltSize; i++) {
    salt[i] = i;
  }

  EXPECT_EQ(Argon2id(salt.data(), "", 0, key.data()), Result::kSuccess);
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
  std::array<uint8_t, 32> buff{};
  bool all_zero = true;

  EXPECT_EQ(Random(buff.data(), 32), Result::kSuccess);

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
  std::array<uint8_t, 32> buff0;
  std::array<uint8_t, 32> buff1;

  Random(buff0.data(), 32);
  Random(buff1.data(), 32);

  EXPECT_NE(memcmp(buff0.data(), buff1.data(), 32), 0);
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

  Result res = RemoveFile(path_);

  EXPECT_EQ(res, Result::kSuccess);
  EXPECT_FALSE(FileExists(path_));
}

/**
 * @brief   Verify RemoveFile fails for non-existent file
 */
TEST_F(RemoveFileTest, DeleteNonExistent) {
  const char* fake = "fake.tmp";

  Result res = RemoveFile(fake);

  EXPECT_EQ(res, Result::kFailure);
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
  EXPECT_EQ(Seek(file_, 0, SEEK_SET), Result::kSuccess);
}

/**
 * @brief   Verify Seek moves to end of file
 */
TEST_F(SeekTest, SeekToEnd) {
  EXPECT_EQ(Seek(file_, 0, SEEK_END), Result::kSuccess);
}

/**
 * @brief   Verify Seek moves to specific position
 */
TEST_F(SeekTest, SeekToMiddle) {
  EXPECT_EQ(Seek(file_, 50, SEEK_SET), Result::kSuccess);
}

/**
 * @brief   Verify Seek with negative offset from end
 */
TEST_F(SeekTest, SeekFromEnd) {
  EXPECT_EQ(Seek(file_, -10, SEEK_END), Result::kSuccess);
}