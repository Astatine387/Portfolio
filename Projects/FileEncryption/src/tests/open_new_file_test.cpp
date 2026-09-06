/**
 * @file    open_new_file_test.cpp
 * @brief   Unit tests for OpenNewFile
 * @author  Astatine387
 */

#include <gtest/gtest.h>

#include <string>

#ifndef _WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#include "utils/platform.h"

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

  /* Poisoned rather than left null, so the assertion below distinguishes a stream that was cleared from
   * one the call never touched. Starting from null would pass either way. */

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
  /* A umask of zero masks nothing away, so the mode checked below can only have come from the open call
   * itself. The case above would still pass if the permissions were being handed out by the process
   * umask and merely happened to agree. */

  const UmaskGuard guard(0);

  ASSERT_EQ(OpenNewFile(&file_, path0_), Result::kSuccess);

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
 *
 * The case exclusive creation is really for. A create that followed the link would find nothing at the
 * far end, decide the name was free, and write the file wherever the link points, which is a path
 * somebody else chose. The check afterwards is that the target is still not there.
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
