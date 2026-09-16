/**
 * @file    utils_test.cpp
 * @brief   Unit tests for utility functions
 * @author  Astatine387
 */

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <string>

#ifndef _WIN32
#include <fcntl.h>
#include <sys/stat.h>
#endif

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
      if (size > 0) {
        std::vector<uint8_t> vec(size, 0x00);

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

  int64_t tmp = GetFileSize(file);

  ASSERT_GT(tmp, 0);
  EXPECT_EQ(tmp, static_cast<int64_t>(strlen(src_data)));

  const size_t fsize = static_cast<size_t>(tmp);

  std::array<char, 32> arr{};

  ASSERT_LE(fsize, arr.size());
  EXPECT_EQ(fread(arr.data(), 1, fsize, file), fsize);

  fclose(file);

  EXPECT_EQ(memcmp(arr.data(), src_data, strlen(src_data)), 0);

  /* Cleanup */

  RemoveFile(dst);
}

/* ==================================================
 * SyncFile Test
 * ================================================== */

/**
 * @class   SyncFileTest
 * @brief   Test class for SyncFile function
 */
class SyncFileTest : public ::testing::Test {
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
   * @brief   Write a small amount of data to the current file
   */
  void Write() {
    const char* data = "Hello, world!";

    fwrite(data, 1, strlen(data), file_);
  }
};

/**
 * @brief   Verify SyncFile succeeds
 */
TEST_F(SyncFileTest, SyncFile) {
  OpenFile(&file_, path_, "wb");
  ASSERT_NE(file_, nullptr);

  Write();

  EXPECT_EQ(SyncFile(file_), Result::kSuccess);
}

/* ==================================================
 * SyncDir Test
 * ================================================== */

/**
 * @brief   Verify SyncDir succeeds for a file in the current directory
 */
TEST(SyncDirTest, CurrentDirectory) {
  EXPECT_EQ(SyncDir("test.tmp"), Result::kSuccess);
}

#ifndef _WIN32

/**
 * @brief   Verify SyncDir fails when the parent directory cannot be opened
 */
TEST(SyncDirTest, OpenFailure) {
  EXPECT_EQ(SyncDir("no_such_dir/test.tmp"), Result::kFailure);
}

#endif /* !_WIN32 */

/* ==================================================
 * OpenTempFile Test
 * ================================================== */

/**
 * @class   OpenTempFileTest
 * @brief   Test class for OpenTempFile function
 */
class OpenTempFileTest : public ::testing::Test {
 protected:
  FILE* file_ = nullptr;
  std::string path_ = "test_temp.XXXXXX";
  std::string dst_ = "test_temp";

  /**
   * @brief   Clean up temporary files after each test
   *
   * A call that succeeded rewrote path_ to the name it created, so removing path_ removes the file wherever the
   * placeholder happened to land. A call that failed left path_ on its template, which names nothing.
   */
  void TearDown() override {
    if (file_) {
      fclose(file_);
      file_ = nullptr;
    }

    RemoveFile(path_);
    RemoveFile(dst_);
  }
};

/**
 * @brief   Verify a valid template is replaced by the name of the file that was created
 */
TEST_F(OpenTempFileTest, ValidTemplate) {
  const std::string tmp = path_;

  ASSERT_EQ(OpenTempFile(&file_, path_), Result::kSuccess);
  ASSERT_NE(file_, nullptr);

  /* The six placeholder characters are replaced where they stand, so the name that comes back is as long as the
   * template and shares its prefix, but is no longer the template itself */

  EXPECT_EQ(path_.size(), tmp.size());
  EXPECT_TRUE(path_.starts_with("test_temp."));
  EXPECT_NE(path_, tmp);
  EXPECT_TRUE(FileExists(path_));
}

/**
 * @brief   Verify a template too short to hold the placeholder fails
 */
TEST_F(OpenTempFileTest, ShortTemplate) {
  path_ = "abc";

  EXPECT_EQ(OpenTempFile(&file_, path_), Result::kFailure);
  EXPECT_EQ(file_, nullptr);
  EXPECT_FALSE(FileExists(path_));
}

#ifndef _WIN32

/**
 * @brief   Verify a template that does not end in the placeholder fails
 *
 * mkstemp refuses such a template outright. The Windows implementation makes no such demand, since it overwrites
 * the last six characters whatever they are, so only the POSIX side can be held to this.
 */
TEST_F(OpenTempFileTest, TemplateWithoutPlaceholder) {
  path_ = "test_temp.suffix";

  EXPECT_EQ(OpenTempFile(&file_, path_), Result::kFailure);
  EXPECT_EQ(file_, nullptr);
  EXPECT_FALSE(FileExists(path_));
}

/**
 * @brief   Verify the descriptor behind the returned stream is closed on exec
 *
 * The vault is written through this stream, so a descriptor that outlived an exec would hand the half-written file
 * to whatever the program spawned.
 */
TEST_F(OpenTempFileTest, SetsCloseOnExec) {
  ASSERT_EQ(OpenTempFile(&file_, path_), Result::kSuccess);
  ASSERT_NE(file_, nullptr);

  const int flags = fcntl(fileno(file_), F_GETFD);

  ASSERT_NE(flags, -1);
  EXPECT_NE(flags & FD_CLOEXEC, 0);
}

/**
 * @brief   Verify a permissive file already sitting at the destination does not widen the temporary
 *
 * Nothing about the destination widens the temporary, whatever mode that destination carries, so a vault left
 * readable by everybody does not pass those bits on to the temporary that replaces it. Only the bits that must never
 * appear are asserted, because the umask in force is free to clear owner bits as well and an exact 0600 would fail
 * on a developer who sets one.
 */
TEST_F(OpenTempFileTest, IgnoresPermissiveDestination) {
  FILE* dst = nullptr;

  OpenFile(&dst, dst_, "wb");
  ASSERT_NE(dst, nullptr);
  fclose(dst);

  ASSERT_EQ(chmod(dst_.c_str(), 0666), 0);

  ASSERT_EQ(OpenTempFile(&file_, path_), Result::kSuccess);
  ASSERT_NE(file_, nullptr);

  struct stat st = {};

  ASSERT_EQ(stat(path_.c_str(), &st), 0);

  /* No group or other bits, and none of setuid, setgid or sticky */

  EXPECT_EQ(st.st_mode & 07077, 0u);
}

#endif /* !_WIN32 */
