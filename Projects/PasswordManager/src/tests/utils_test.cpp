/**
 * @file    utils_test.cpp
 * @brief   Unit tests for utility functions
 * @author  Astatine387
 */

#include <gtest/gtest.h>

#include <algorithm>
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
      std::vector<uint8_t> vec(size, 0x00);

      fwrite(vec.data(), 1, size, file_);

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

    if (file)
      fclose(file);
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
 * @brief   Verify FileExists returns false for non-existing file
 */
TEST_F(FileExistsTest, NonExistingFile) {
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
  size_t size = strlen(pw);

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
  size_t size0 = strlen(pw0);
  size_t size1 = strlen(pw1);

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
  size_t size = strlen(pw);

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
  std::array<uint8_t, 32> arr{};
  bool all_zero = true;

  EXPECT_EQ(Random(arr.data(), 32), Result::kSuccess);

  for (int i = 0; i < 32; i++) {
    if (arr[i]) {
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
  std::array<uint8_t, 32> arr0;
  std::array<uint8_t, 32> arr1;

  Random(arr0.data(), 32);
  Random(arr1.data(), 32);

  EXPECT_NE(memcmp(arr0.data(), arr1.data(), 32), 0);
}

/* ==================================================
 * RandomRange Test
 * ================================================== */

/**
 * @brief   Verify RandomRange generates values within the specified range
 */
TEST(RandomRangeTest, WithinRange) {
  for (int i = 0; i < 100; i++) {
    uint32_t val;

    EXPECT_EQ(RandomRange(&val, 0, 9), Result::kSuccess);
    EXPECT_GE(val, 0u);
    EXPECT_LE(val, 9u);
  }
}

/**
 * @brief   Verify RandomRange works with min == max
 */
TEST(RandomRangeTest, MinEqualsMax) {
  for (int i = 0; i < 10; i++) {
    uint32_t val;

    EXPECT_EQ(RandomRange(&val, 0, 0), Result::kSuccess);
    EXPECT_EQ(val, 0u);
  }
}

/**
 * @brief   Verify RandomRange fails when the range overflows to zero
 */
TEST(RandomRangeTest, ZeroRange) {
  uint32_t val;

  EXPECT_EQ(RandomRange(&val, 0, UINT32_MAX), Result::kFailure);
}

/**
 * @brief   Verify RandomRange fails when min is greater than max
 */
TEST(RandomRangeTest, MinGreaterThanMax) {
  uint32_t val;

  EXPECT_EQ(RandomRange(&val, 10, 5), Result::kFailure);
}

/* ==================================================
 * RenameFile Test
 * ================================================== */

/**
 * @brief   Verify renaming a file succeeds
 */
TEST(UtilsTest, RenameFileBasic) {
  std::string src = "rename_src.tmp";
  std::string dst = "rename_dst.tmp";

  /* Create source file */

  FILE* file = nullptr;

  OpenFile(&file, src, "wb");
  ASSERT_NE(file, nullptr);

  const char* data = "test data";

  fwrite(data, 1, strlen(data), file);
  fclose(file);

  EXPECT_TRUE(FileExists(src));

  /* Rename */

  EXPECT_EQ(RenameFile(src, dst), Result::kSuccess);
  EXPECT_FALSE(FileExists(src));
  EXPECT_TRUE(FileExists(dst));

  /* Cleanup */

  RemoveFile(dst);
}

/**
 * @brief   Verify renaming a non-existent file fails
 */
TEST(UtilsTest, RenameFileNonExistent) {
  EXPECT_EQ(RenameFile("nonexistent.tmp", "dst.tmp"), Result::kFailure);
}

/**
 * @brief   Verify renaming overwrites existing destination file
 */
TEST(UtilsTest, RenameFileOverwrite) {
  std::string src = "src.tmp";
  std::string dst = "dst.tmp";

  /* Create source file */

  FILE* file = nullptr;

  OpenFile(&file, src, "wb");
  ASSERT_NE(file, nullptr);

  const char* src_data = "Hello, world!";

  fwrite(src_data, 1, strlen(src_data), file);
  fclose(file);

  /* Create destination file with different data */

  OpenFile(&file, dst, "wb");
  ASSERT_NE(file, nullptr);

  const char* dst_data = "Goodbye, world!";

  fwrite(dst_data, 1, strlen(dst_data), file);
  fclose(file);

  EXPECT_TRUE(FileExists(src));
  EXPECT_TRUE(FileExists(dst));

  /* Rename (overwrite) */

  EXPECT_EQ(RenameFile(src, dst), Result::kSuccess);
  EXPECT_FALSE(FileExists(src));
  EXPECT_TRUE(FileExists(dst));

  /* Verify destination contains source data */

  OpenFile(&file, dst, "rb");
  ASSERT_NE(file, nullptr);

  int64_t size = GetFileSize(file);

  EXPECT_EQ(size, static_cast<int64_t>(strlen(src_data)));

  std::array<char, 32> arr{};

  fread(arr.data(), 1, size, file);
  fclose(file);

  EXPECT_EQ(memcmp(arr.data(), src_data, strlen(src_data)), 0);

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
  std::array<uint8_t, 32> arr;

  arr.fill(0xff);

  Wipe(arr.data(), 32);

  for (int i = 0; i < 32; i++) {
    EXPECT_EQ(arr[i], 0);
  }
}

/**
 * @brief   Verify Wipe zeroes only the specified portion
 */
TEST(WipeTest, WipePartial) {
  std::array<uint8_t, 32> arr;

  arr.fill(0xff);

  Wipe(arr.data(), 16);

  for (int i = 0; i < 16; i++) {
    EXPECT_EQ(arr[i], 0);
  }

  for (int i = 16; i < 32; i++) {
    EXPECT_EQ(arr[i], 0xFF);
  }
}

/* ==================================================
 * Shuffle Test
 * ================================================== */

/**
 * @brief   Verify Shuffle preserves all elements
 */
TEST(ShuffleTest, PreservesElements) {
  std::array<uint8_t, 10> arr;

  for (uint8_t i = 0; i < 10; i++) {
    arr[i] = i;
  }

  EXPECT_EQ(Shuffle(arr.data(), arr.size()), Result::kSuccess);

  /* Sort and verify all elements are preserved */

  std::vector<uint8_t> sorted(arr.begin(), arr.end());

  std::ranges::sort(sorted);

  for (int i = 0; i < 10; i++) {
    EXPECT_EQ(sorted[i], i);
  }
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