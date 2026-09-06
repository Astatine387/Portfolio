/**
 * @file    utils_test.cpp
 * @brief   Unit tests for utility functions
 * @author  Astatine387
 *
 * Several of the fixtures below name the same scratch file, and all of them work in the directory the
 * suite is run from, so two of these cases running at once would be writing over each other. The suite
 * has to run serially.
 */

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <string>
#include <string_view>

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

  EXPECT_EQ(Random(buff.data(), buff.size()), Result::kSuccess);

  const bool all_zero = std::ranges::all_of(buff, [](uint8_t b) { return b == 0; });

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

/**
 * @brief   Verify Seek fails on a negative absolute offset
 */
TEST_F(SeekTest, SeekBeforeBeginningFails) {
  EXPECT_EQ(Seek(file_, -1, SEEK_SET), Result::kFailure);
}

/* ==================================================
 * Durability Helper Tests
 * ================================================== */

/**
 * @class   DurabilityTest
 * @brief   Test class for RenameNoReplace, SyncFile and SyncDir
 */
class DurabilityTest : public ::testing::Test {
 protected:
  std::string src_path_ = "durability_src.tmp";
  std::string dst_path_ = "durability_dst.tmp";

  /**
   * @brief   Clean up temporary files after each test
   */
  void TearDown() override {
    RemoveFile(src_path_);
    RemoveFile(dst_path_);
  }

  /**
   * @brief   Create a file holding the given text
   * @param   path    File path
   * @param   text    Content to write
   */
  static void Create(const std::string& path, const std::string& text) {
    FILE* file = nullptr;

    OpenFile(&file, path, "wb");

    ASSERT_NE(file, nullptr);

    EXPECT_EQ(fwrite(text.data(), sizeof(char), text.size(), file), text.size());

    fclose(file);
  }

  /**
   * @brief   Read a file back as text
   * @param   path    File path
   * @return  File contents, empty when the file cannot be read
   */
  static std::string Read(const std::string& path) {
    FILE* file = nullptr;
    std::string res;

    OpenFile(&file, path, "rb");

    if (!file) {
      return res;
    }

    std::array<char, 128> buff{};

    res.assign(buff.data(), fread(buff.data(), sizeof(char), buff.size(), file));

    fclose(file);

    return res;
  }
};

/**
 * @brief   Verify a move onto a free path carries the content and drops the source
 */
TEST_F(DurabilityTest, MovesOntoFreePath) {
  Create(src_path_, "Hello, world!");

  EXPECT_EQ(RenameFile(src_path_, dst_path_), Result::kSuccess);

  EXPECT_FALSE(FileExists(src_path_));
  EXPECT_TRUE(FileExists(dst_path_));
  EXPECT_EQ(Read(dst_path_), "Hello, world!");
}

/**
 * @brief   Verify an occupied destination is refused and both files survive untouched
 */
TEST_F(DurabilityTest, RefusesOccupiedDestination) {
  Create(src_path_, "Hello, world!");
  Create(dst_path_, "Don't overwrite this");

  EXPECT_EQ(RenameFile(src_path_, dst_path_), Result::kFailure);

  EXPECT_EQ(Read(src_path_), "Hello, world!");
  EXPECT_EQ(Read(dst_path_), "Don't overwrite this");
}

/**
 * @brief   Verify a missing source is refused rather than creating an empty destination
 */
TEST_F(DurabilityTest, RefusesMissingSource) {
  EXPECT_EQ(RenameFile(src_path_, dst_path_), Result::kFailure);
  EXPECT_FALSE(FileExists(dst_path_));
}

/**
 * @brief   Verify syncing a written file reports success and the bytes are readable after
 */
TEST_F(DurabilityTest, SyncsFileContents) {
  FILE* file = nullptr;

  OpenFile(&file, src_path_, "wb");

  ASSERT_NE(file, nullptr);

  EXPECT_EQ(fwrite("Hello, world!", sizeof(char), 13, file), 13U);
  EXPECT_EQ(SyncFile(file), Result::kSuccess);

  fclose(file);

  EXPECT_EQ(Read(src_path_), "Hello, world!");
}

/**
 * @brief   Verify the parent directory of a path can be synced
 */
TEST_F(DurabilityTest, SyncsParentDirectory) {
  Create(src_path_, "Hello, world!");

  EXPECT_EQ(SyncDir(src_path_), Result::kSuccess);
}

/**
 * @brief   Verify syncing reports failure when the parent directory does not exist
 */
TEST_F(DurabilityTest, SyncDirRejectsMissingDirectory) {
  EXPECT_EQ(SyncDir("fake/file.tmp"), Result::kFailure);
}

#ifndef _WIN32

/**
 * @brief   Verify syncing reports failure when the buffered bytes cannot reach the device
 */
TEST_F(DurabilityTest, SyncFileRejectsFullDevice) {
  FILE* file = nullptr;

  OpenFile(&file, "/dev/full", "wb");

  if (file == nullptr) {
    GTEST_SKIP() << "/dev/full is not available";
  }

  EXPECT_EQ(fwrite("Hello, world!", sizeof(char), 13, file), 13U);
  EXPECT_EQ(SyncFile(file), Result::kFailure);

  fclose(file);
}

#endif  // !_WIN32
