/**
 * @file    utils_test.cpp
 * @brief   Unit tests for utility functions
 * @author  Astatine387
 */

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <string>
#include <string_view>

#ifndef _WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
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
 * OpenNewFile Test
 * ================================================== */

/**
 * @class   OpenNewFileTest
 * @brief   Test class for OpenNewFile function
 */
class OpenNewFileTest : public ::testing::Test {
 protected:
  FILE* file_ = nullptr;
  std::string path0_ = "test0.tmp";
  std::string path1_ = "test1.tmp";

  /**
   * @brief   Clean up temporary files and links after each test
   */
  void TearDown() override {
    if (file_) {
      fclose(file_);
      file_ = nullptr;
    }

    RemoveFile(path0_);
    RemoveFile(path1_);
  }

  /**
   * @brief   Create a plain file holding the given text
   * @param   path    File path
   * @param   text    Contents to write
   */
  static void Create(const std::string& path, const char* text) {
    FILE* file = nullptr;

    OpenFile(&file, path, "wb");

    ASSERT_NE(file, nullptr);

    fwrite(text, 1, strlen(text), file);
    fclose(file);
  }

  /**
   * @brief   Read back a file as a string
   * @param   path    File path
   * @return  File contents, empty when read fails
   */
  static std::string Read(const std::string& path) {
    FILE* file = nullptr;
    std::string out;

    OpenFile(&file, path, "rb");

    if (!file) {
      return out;
    }

    std::array<char, 256> buff{};

    const size_t read = fread(buff.data(), 1, buff.size(), file);

    out.assign(buff.data(), read);

    fclose(file);

    return out;
  }
};

/**
 * @brief   Verify OpenNewFile creates a file that doesn't exist
 */
TEST_F(OpenNewFileTest, CreatesNewFile) {
  ASSERT_EQ(OpenNewFile(&file_, path0_), Result::kSuccess);
  ASSERT_NE(file_, nullptr);

  EXPECT_TRUE(FileExists(path0_));
}

/**
 * @brief   Verify OpenNewFile refuses a path that already exists
 */
TEST_F(OpenNewFileTest, RefusesExistingFile) {
  Create(path0_, "Hello, world!");

  EXPECT_EQ(OpenNewFile(&file_, path0_), Result::kFailure);
}

/**
 * @brief   Verify a refused call leaves the existing file untouched
 */
TEST_F(OpenNewFileTest, KeepsExistingFileIntact) {
  Create(path0_, "Hello, world!");

  ASSERT_EQ(OpenNewFile(&file_, path0_), Result::kFailure);
  EXPECT_EQ(Read(path0_), "Hello, world!");
}

/**
 * @brief   Verify the stream is left null when the call fails
 */
TEST_F(OpenNewFileTest, NullsStreamOnFailure) {
  Create(path0_, "x");

  file_ = reinterpret_cast<FILE*>(0x1);  // NOLINT(performance-no-int-to-ptr)

  ASSERT_EQ(OpenNewFile(&file_, path0_), Result::kFailure);
  EXPECT_EQ(file_, nullptr);

  file_ = nullptr;  // Keep TearDown from closing the poisoned value
}

/**
 * @brief   Verify OpenNewFile fails when the parent directory doesn't exist
 */
TEST_F(OpenNewFileTest, RefusesMissingDirectory) {
  EXPECT_EQ(OpenNewFile(&file_, "fake/fake.tmp"), Result::kFailure);
  EXPECT_EQ(file_, nullptr);
}

/**
 * @brief   Verify a file created by OpenNewFile is writable through the returned stream
 */
TEST_F(OpenNewFileTest, StreamIsWritable) {
  ASSERT_EQ(OpenNewFile(&file_, path0_), Result::kSuccess);

  constexpr std::string_view kText = "Hello, world!";

  ASSERT_EQ(fwrite(kText.data(), 1, kText.size(), file_), kText.size());

  fclose(file_);
  file_ = nullptr;

  EXPECT_EQ(Read(path0_), "Hello, world!");
}

#ifndef _WIN32

/**
 * @class   UmaskGuard
 * @brief   Pin the process umask for a scope and restore it on the way out
 */
class UmaskGuard {
 public:
  explicit UmaskGuard(mode_t mask) : tmp_(umask(mask)) {}

  ~UmaskGuard() { umask(tmp_); }

  UmaskGuard(const UmaskGuard&) = delete;
  UmaskGuard& operator=(const UmaskGuard&) = delete;
  UmaskGuard(UmaskGuard&&) = delete;
  UmaskGuard& operator=(UmaskGuard&&) = delete;

 private:
  mode_t tmp_;
};

/**
 * @brief   Verify the created file is readable and writable by the owner only
 */
TEST_F(OpenNewFileTest, CreatesOwnerOnlyFile) {
  const UmaskGuard guard(0022);

  ASSERT_EQ(OpenNewFile(&file_, path0_), Result::kSuccess);

  struct stat st = {};

  ASSERT_EQ(fstat(fileno(file_), &st), 0);
  EXPECT_EQ(st.st_mode & 07777U, 0600U) << "mode is 0" << std::oct << (st.st_mode & 07777U);
}

/**
 * @brief   Verify the permission guarantee does not depend on the caller's umask
 */
TEST_F(OpenNewFileTest, IgnoresPermissiveUmask) {
  const UmaskGuard guard(0);

  ASSERT_EQ(OpenNewFile(&file_, path0_), Result::kSuccess);  // 이제 조기 반환해도 안전

  struct stat st = {};

  ASSERT_EQ(fstat(fileno(file_), &st), 0);
  EXPECT_EQ(st.st_mode & 07777U, 0600U) << "mode is 0" << std::oct << (st.st_mode & 07777U);
}

/**
 * @brief   Verify the descriptor is not inherited across exec
 */
TEST_F(OpenNewFileTest, SetsCloseOnExec) {
  ASSERT_EQ(OpenNewFile(&file_, path0_), Result::kSuccess);

  const int flags = fcntl(fileno(file_), F_GETFD);

  ASSERT_NE(flags, -1);
  EXPECT_NE(flags & FD_CLOEXEC, 0);
}

/**
 * @brief   Verify a dangling symbolic link at the destination is refused
 */
TEST_F(OpenNewFileTest, RefusesDanglingSymlink) {
  ASSERT_EQ(symlink(path1_.c_str(), path0_.c_str()), 0);

  ASSERT_FALSE(FileExists(path0_));
  ASSERT_FALSE(FileExists(path1_));
  ASSERT_EQ(OpenNewFile(&file_, path0_), Result::kFailure);
  EXPECT_EQ(errno, EEXIST);
  EXPECT_EQ(file_, nullptr);

  EXPECT_FALSE(FileExists(path1_));

  struct stat st = {};

  ASSERT_EQ(lstat(path0_.c_str(), &st), 0);
  EXPECT_TRUE(S_ISLNK(st.st_mode));
}

/**
 * @brief   Verify a symbolic link to an existing file is refused and the target survives
 */
TEST_F(OpenNewFileTest, RefusesSymlinkToExistingFile) {
  Create(path1_, "Hello, world!");

  ASSERT_EQ(symlink(path1_.c_str(), path0_.c_str()), 0);
  ASSERT_EQ(OpenNewFile(&file_, path0_), Result::kFailure);
  EXPECT_EQ(Read(path1_), "Hello, world!");
}

/**
 * @brief   Verify a FIFO at the destination is refused rather than blocking on a reader
 */
TEST_F(OpenNewFileTest, RefusesFifo) {
  ASSERT_EQ(mkfifo(path0_.c_str(), 0600), 0);
  EXPECT_EQ(OpenNewFile(&file_, path0_), Result::kFailure);
}

#endif  // !_WIN32
