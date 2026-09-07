/**
 * @file    open_source_file_test.cpp
 * @brief   Unit tests for OpenSourceFile
 * @author  Astatine387
 *
 * The fixture names scratch files in the directory the suite is run from, the same as the other
 * fixtures here, so these cases rely on the RUN_SERIAL property in CMakeLists.txt.
 */

#include <gtest/gtest.h>

#include <string>

#include "utils/platform.h"

/* ==================================================
 * OpenSourceFile Test
 * ================================================== */

/**
 * @class   OpenSourceFileTest
 * @brief   Test class for OpenSourceFile function
 */
class OpenSourceFileTest : public ::testing::Test {
 protected:
  FILE* file_ = nullptr;
  std::string path_ = "source.tmp";

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
   * @brief   Create a plain file holding the given text
   * @param   path    File path
   * @param   text    Contents to write
   */
  static void Create(const std::string& path, const std::string& text) {
    FILE* file = nullptr;

    OpenFile(&file, path, "wb");

    ASSERT_NE(file, nullptr);

    if (!text.empty()) {
      EXPECT_EQ(fwrite(text.data(), sizeof(char), text.size(), file), text.size());
    }

    fclose(file);
  }
};

/**
 * @brief   Verify an ordinary file opens and reads back through the returned stream
 */
TEST_F(OpenSourceFileTest, ReadsRegularFile) {
  Create(path_, "Hello, world!");

  ASSERT_EQ(OpenSourceFile(&file_, path_), Result::kSuccess);
  ASSERT_NE(file_, nullptr);

  std::array<char, 32> buff{};

  const size_t read = fread(buff.data(), sizeof(char), buff.size(), file_);

  EXPECT_EQ(std::string(buff.data(), read), "Hello, world!");
}

/**
 * @brief   Verify an empty file is accepted rather than mistaken for a pseudo file
 *
 * The size of zero sends this one through the same probe that refuses a procfs entry below, so the
 * case is here to hold the line between the two: nothing to read means an ordinary empty file.
 */
TEST_F(OpenSourceFileTest, AcceptsEmptyFile) {
  Create(path_, "");

  ASSERT_EQ(OpenSourceFile(&file_, path_), Result::kSuccess);
  EXPECT_NE(file_, nullptr);
  EXPECT_EQ(GetFileSize(file_), 0);
}

#ifndef _WIN32

/**
 * @brief   Verify a directory is refused rather than opened as a source
 */
TEST_F(OpenSourceFileTest, RefusesDirectory) {
  EXPECT_EQ(OpenSourceFile(&file_, "."), Result::kFailure);
  EXPECT_EQ(file_, nullptr);
}

/**
 * @brief   Verify a pseudo file that reports a size of zero while holding contents is refused
 *
 * The case the read probe exists for. A procfs entry is a regular file by st_mode and answers every
 * check before the probe, so without it the file would be encrypted into an empty output and the run
 * reported as a success.
 */
TEST_F(OpenSourceFileTest, RefusesPseudoFileReportingZeroSize) {
  constexpr const char* kPseudoPath = "/proc/self/status";

  if (!FileExists(kPseudoPath)) {
    GTEST_SKIP() << "procfs is not mounted";
  }

  EXPECT_EQ(OpenSourceFile(&file_, kPseudoPath), Result::kFailure);
  EXPECT_EQ(file_, nullptr);
}

#endif  // !_WIN32
