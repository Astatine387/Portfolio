/**
 * @file    file_header_test.cpp
 * @brief   Unit tests for encrypted file header handling
 * @author  Astatine387
 */

#include "core/file_header.h"

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "utils/platform.h"

/**
 * @class   FileHeaderTest
 * @brief   Test fixture for header reading, writing and validation
 */
class FileHeaderTest : public ::testing::Test {
 protected:
  std::string path_ = "header_test.tmp";

  /**
   * @brief   Clean up temporary files after each test
   */
  void TearDown() override { RemoveFile(path_); }

  /**
   * @brief   Build a header whose every field is distinguishable
   * @param   params  Argon2id parameters to store
   * @return  Header filled with recognizable salt and IV bytes
   */
  static FileHeader MakeHeader(const KdfParams& params = {}) {
    FileHeader header;

    header.params = params;
    header.salt.fill(0xA5);
    header.iv.fill(0x5A);

    return header;
  }

  /**
   * @brief   Write raw bytes over the test file
   * @param   buff    Bytes to write
   */
  void WriteRaw(const std::vector<uint8_t>& buff) {
    FILE* file = nullptr;

    OpenFile(&file, path_, "wb");

    ASSERT_NE(file, nullptr);

    if (!buff.empty()) {
      EXPECT_EQ(fwrite(buff.data(), sizeof(uint8_t), buff.size(), file), buff.size());
    }

    fclose(file);
  }

  /**
   * @brief   Write a header to the test file
   * @param   header  Header to store
   */
  void Store(const FileHeader& header) {
    FILE* file = nullptr;

    OpenFile(&file, path_, "wb");

    ASSERT_NE(file, nullptr);

    EXPECT_EQ(WriteHeader(file, header), Result::kSuccess);

    fclose(file);
  }

  /**
   * @brief   Read the test file back into a byte vector
   * @return  File contents
   */
  std::vector<uint8_t> Load() {
    FILE* file = nullptr;
    std::vector<uint8_t> buff;

    OpenFile(&file, path_, "rb");

    if (!file) {
      return buff;  // LCOV_EXCL_LINE
    }

    const int64_t size = GetFileSize(file);

    if (size > 0) {
      buff.resize(static_cast<size_t>(size));

      EXPECT_EQ(fread(buff.data(), sizeof(uint8_t), buff.size(), file), buff.size());
    }

    fclose(file);

    return buff;
  }

  /**
   * @brief   Read a header back from the test file
   * @param   header  Destination header
   * @return  Status reported by ReadHeader
   */
  HeaderStatus Reload(FileHeader& header) {
    FILE* file = nullptr;

    OpenFile(&file, path_, "rb");

    if (!file) {
      return HeaderStatus::kReadError;  // LCOV_EXCL_LINE
    }

    const HeaderStatus status = ReadHeader(file, header);

    fclose(file);

    return status;
  }
};

/* ==================================================
 * Layout Tests
 * ================================================== */

/**
 * @brief   Verify a written header reads back field for field
 */
TEST_F(FileHeaderTest, RoundTrip) {
  const FileHeader src = MakeHeader();
  FileHeader dst;

  Store(src);

  EXPECT_EQ(Reload(dst), HeaderStatus::kOk);

  EXPECT_EQ(dst.params.time_cost, src.params.time_cost);
  EXPECT_EQ(dst.params.mem_cost, src.params.mem_cost);
  EXPECT_EQ(dst.params.parallelism, src.params.parallelism);
  EXPECT_EQ(dst.salt, src.salt);
  EXPECT_EQ(dst.iv, src.iv);
}

/**
 * @brief   Verify non-default parameters survive the round-trip rather than the build defaults
 */
TEST_F(FileHeaderTest, RoundTripKeepsNonDefaultParams) {
  const KdfParams params{ .time_cost = kMaxTimeCost, .mem_cost = kMinMemCost, .parallelism = kMaxParallelism };
  FileHeader dst;

  Store(MakeHeader(params));

  EXPECT_EQ(Reload(dst), HeaderStatus::kOk);

  EXPECT_EQ(dst.params.time_cost, kMaxTimeCost);
  EXPECT_EQ(dst.params.mem_cost, kMinMemCost);
  EXPECT_EQ(dst.params.parallelism, kMaxParallelism);
}

/**
 * @brief   Verify the header occupies exactly the documented byte layout
 */
TEST_F(FileHeaderTest, WritesDocumentedLayout) {
  const KdfParams params{ .time_cost = 7, .mem_cost = 12345, .parallelism = 3 };
  const FileHeader header = MakeHeader(params);

  Store(header);

  const std::vector<uint8_t> buff = Load();

  ASSERT_EQ(buff.size(), kDataOffset);

  uint32_t field = 0;

  memcpy(&field, buff.data(), kMagicSize);
  EXPECT_EQ(field, kMagicNum);

  memcpy(&field, buff.data() + kMagicSize, sizeof(uint32_t));
  EXPECT_EQ(field, params.time_cost);

  memcpy(&field, buff.data() + kMagicSize + sizeof(uint32_t), sizeof(uint32_t));
  EXPECT_EQ(field, params.mem_cost);

  memcpy(&field, buff.data() + kMagicSize + 2 * sizeof(uint32_t), sizeof(uint32_t));
  EXPECT_EQ(field, params.parallelism);

  EXPECT_EQ(memcmp(buff.data() + kKdfParamSize, header.salt.data(), kSaltSize), 0);
  EXPECT_EQ(memcmp(buff.data() + kKdfParamSize + kSaltSize, header.iv.data(), kIVSize), 0);
}

/**
 * @brief   Verify reading starts from the beginning and stops at the ciphertext
 */
TEST_F(FileHeaderTest, ReadLeavesCursorAtData) {
  FILE* file = nullptr;
  FileHeader header;

  Store(MakeHeader());

  OpenFile(&file, path_, "rb");

  ASSERT_NE(file, nullptr);

  /* Start from somewhere other than the beginning to prove the read seeks first */

  EXPECT_EQ(Seek(file, 3, SEEK_SET), Result::kSuccess);
  EXPECT_EQ(ReadHeader(file, header), HeaderStatus::kOk);
  EXPECT_EQ(ftell(file), static_cast<long>(kDataOffset));

  fclose(file);
}

/* ==================================================
 * Rejection Tests
 * ================================================== */

/**
 * @brief   Verify a file written by another tool is rejected on the magic number
 */
TEST_F(FileHeaderTest, RejectsForeignMagic) {
  std::vector<uint8_t> buff(kDataOffset, 0x00);
  FileHeader header;

  WriteRaw(buff);

  EXPECT_EQ(Reload(header), HeaderStatus::kBadMagic);
}

/**
 * @brief   Verify a header one byte short of complete is rejected as unreadable
 */
TEST_F(FileHeaderTest, RejectsTruncatedHeader) {
  FileHeader header;

  Store(MakeHeader());

  std::vector<uint8_t> buff = Load();

  ASSERT_EQ(buff.size(), kDataOffset);

  buff.pop_back();

  WriteRaw(buff);

  EXPECT_EQ(Reload(header), HeaderStatus::kReadError);
}

/**
 * @brief   Verify an empty file is rejected as unreadable
 */
TEST_F(FileHeaderTest, RejectsEmptyFile) {
  FileHeader header;

  WriteRaw({});

  EXPECT_EQ(Reload(header), HeaderStatus::kReadError);
}

/* ==================================================
 * Parameter Validation Tests
 * ================================================== */

/**
 * @brief   Verify the build defaults pass validation
 */
TEST_F(FileHeaderTest, AcceptsDefaultParams) {
  EXPECT_EQ(ValidateKdfParams(KdfParams{}), HeaderStatus::kOk);
}

/**
 * @brief   Verify both ends of the accepted range pass validation
 */
TEST_F(FileHeaderTest, AcceptsBoundaryParams) {
  const KdfParams low{ .time_cost = kMinTimeCost, .mem_cost = kMinMemCost, .parallelism = kMinParallelism };
  const KdfParams high{ .time_cost = kMaxTimeCost, .mem_cost = kMaxMemCost, .parallelism = kMaxParallelism };

  EXPECT_EQ(ValidateKdfParams(low), HeaderStatus::kOk);
  EXPECT_EQ(ValidateKdfParams(high), HeaderStatus::kOk);
}

/**
 * @brief   Verify a field just outside the accepted range is rejected
 */
TEST_F(FileHeaderTest, RejectsOutOfRangeParams) {
  const std::array<KdfParams, 6> cases{
    KdfParams{ .time_cost = kMinTimeCost - 1, .mem_cost = kMemCost, .parallelism = kParallelism },
    KdfParams{ .time_cost = kMaxTimeCost + 1, .mem_cost = kMemCost, .parallelism = kParallelism },
    KdfParams{ .time_cost = kTimeCost, .mem_cost = kMinMemCost - 1, .parallelism = kParallelism },
    KdfParams{ .time_cost = kTimeCost, .mem_cost = kMaxMemCost + 1, .parallelism = kParallelism },
    KdfParams{ .time_cost = kTimeCost, .mem_cost = kMemCost, .parallelism = kMinParallelism - 1 },
    KdfParams{ .time_cost = kTimeCost, .mem_cost = kMemCost, .parallelism = kMaxParallelism + 1 },
  };

  for (const KdfParams& params : cases) {
    SCOPED_TRACE(testing::Message() << "t=" << params.time_cost << " m=" << params.mem_cost
                                    << " p=" << params.parallelism);

    EXPECT_EQ(ValidateKdfParams(params), HeaderStatus::kBadParams);
  }
}

/**
 * @brief   Verify parameters are returned as stored so the caller decides whether to trust them
 */
TEST_F(FileHeaderTest, ReadDoesNotValidateParams) {
  const KdfParams params{ .time_cost = kMaxTimeCost + 1, .mem_cost = kMaxMemCost + 1, .parallelism = 0 };
  FileHeader header;

  Store(MakeHeader(params));

  EXPECT_EQ(Reload(header), HeaderStatus::kOk);
  EXPECT_EQ(ValidateKdfParams(header.params), HeaderStatus::kBadParams);
}

/* ==================================================
 * Message Tests
 * ================================================== */

/**
 * @brief   Verify every failure carries a distinct reportable message
 */
TEST_F(FileHeaderTest, ErrorMessagesAreDistinct) {
  const std::string read_error = HeaderErrorMessage(HeaderStatus::kReadError);
  const std::string bad_magic = HeaderErrorMessage(HeaderStatus::kBadMagic);
  const std::string bad_params = HeaderErrorMessage(HeaderStatus::kBadParams);

  EXPECT_FALSE(read_error.empty());
  EXPECT_FALSE(bad_magic.empty());
  EXPECT_FALSE(bad_params.empty());

  EXPECT_NE(read_error, bad_magic);
  EXPECT_NE(read_error, bad_params);
  EXPECT_NE(bad_magic, bad_params);

  EXPECT_STREQ(HeaderErrorMessage(HeaderStatus::kOk), "");
}
