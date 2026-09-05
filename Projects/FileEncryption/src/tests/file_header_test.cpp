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

#include "utils/byte_order.h"
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
   * @param   params      Argon2id parameters to store
   * @param   chunk_log2  Base-2 logarithm of the chunk size to store
   * @return  Header filled with recognizable salt bytes
   */
  static FileHeader MakeHeader(const KdfParams& params = {}, uint8_t chunk_log2 = kChunkSizeLog2) {
    FileHeader header;

    header.chunk_log2 = chunk_log2;
    header.params = params;
    header.salt.fill(0xA5);

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
    std::vector<uint8_t> buff;
    FILE* file = nullptr;

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
  const std::array<FileHeader, 4> cases{
    MakeHeader(),  // Default values
    MakeHeader({ .time_cost = kMinTimeCost, .mem_cost = kMinMemCost, .parallelism = kMinParallelism },
               kMinChunkSizeLog2),  // Minimum values
    MakeHeader({ .time_cost = kMaxTimeCost, .mem_cost = kMaxMemCost, .parallelism = kMaxParallelism },
               kMaxChunkSizeLog2),                                                      // Maximum values
    MakeHeader({ .time_cost = 3, .mem_cost = 2 * kMinMemCost, .parallelism = 7 }, 14),  // Arbitrary values
  };

  for (const FileHeader& src : cases) {
    SCOPED_TRACE(testing::Message() << "chunk_log2=" << static_cast<int>(src.chunk_log2)
                                    << " t=" << src.params.time_cost << " m=" << src.params.mem_cost
                                    << " p=" << src.params.parallelism);

    FileHeader dst;

    Store(src);

    EXPECT_EQ(Reload(dst), HeaderStatus::kOk);

    EXPECT_EQ(dst.params.time_cost, src.params.time_cost);
    EXPECT_EQ(dst.params.mem_cost, src.params.mem_cost);
    EXPECT_EQ(dst.params.parallelism, src.params.parallelism);
    EXPECT_EQ(dst.salt, src.salt);
    EXPECT_EQ(dst.chunk_log2, src.chunk_log2);
  }
}

/**
 * @brief   Verify the header occupies exactly the documented byte layout
 */
TEST_F(FileHeaderTest, WritesDocumentedLayout) {
  const KdfParams params{ .time_cost = 7, .mem_cost = 12345, .parallelism = 3 };

  FileHeader header = MakeHeader(params, 14);

  for (size_t i = 0; i < kSaltSize; i++) {
    header.salt[i] = static_cast<uint8_t>(0xB0 + i);
  }

  Store(header);

  const std::vector<uint8_t> buff = Load();

  ASSERT_EQ(buff.size(), kHeaderSize);

  EXPECT_EQ(memcmp(buff.data(), kMagic.data(), kMagicSize), 0);
  EXPECT_EQ(buff[4], 14);
  EXPECT_EQ(LoadLE32(buff.data() + 5), 7U);
  EXPECT_EQ(LoadLE32(buff.data() + 9), 12345U);
  EXPECT_EQ(LoadLE32(buff.data() + 13), 3U);

  EXPECT_EQ(memcmp(buff.data() + 17, header.salt.data(), kSaltSize), 0);
}

/**
 * @brief   Verify reading starts from the beginning and stops at the ciphertext
 */
TEST_F(FileHeaderTest, ReadLeavesCursorAtData) {
  FileHeader header;
  FILE* file = nullptr;

  Store(MakeHeader());
  OpenFile(&file, path_, "rb");

  ASSERT_NE(file, nullptr);

  EXPECT_EQ(Seek(file, 3, SEEK_SET), Result::kSuccess);
  EXPECT_EQ(ReadHeader(file, header), HeaderStatus::kOk);
  EXPECT_EQ(ftell(file), static_cast<long>(kHeaderSize));

  fclose(file);
}

/* ==================================================
 * Rejection Tests
 * ================================================== */

/**
 * @brief   Verify a file with wrong magic number is rejected
 */
TEST_F(FileHeaderTest, RejectsForeignMagic) {
  std::vector<uint8_t> buff(kHeaderSize, 0x00);
  FileHeader header;

  WriteRaw(buff);

  EXPECT_EQ(Reload(header), HeaderStatus::kBadMagic);
}

/**
 * @brief   Verify any file too short to hold a whole header is rejected as unreadable
 */
TEST_F(FileHeaderTest, RejectsShortFile) {
  const std::array<size_t, 3> cases{ 0, 1, kHeaderSize - 1 };

  for (size_t size : cases) {
    SCOPED_TRACE(testing::Message() << "size=" << size);

    FileHeader header;

    WriteRaw(std::vector<uint8_t>(size, 0x00));

    EXPECT_EQ(Reload(header), HeaderStatus::kReadError);
  }
}

/* ==================================================
 * Header Validation Tests
 * ================================================== */

/**
 * @brief   Verify the build defaults pass validation
 */
TEST_F(FileHeaderTest, AcceptsDefaultHeader) {
  EXPECT_EQ(ValidateHeader(FileHeader{}), HeaderStatus::kOk);
}

/**
 * @brief   Verify both ends of the accepted range pass validation
 */
TEST_F(FileHeaderTest, AcceptsBoundaryHeader) {
  const KdfParams min_params{ .time_cost = kMinTimeCost, .mem_cost = kMinMemCost, .parallelism = kMinParallelism };
  const KdfParams max_params{ .time_cost = kMaxTimeCost, .mem_cost = kMaxMemCost, .parallelism = kMaxParallelism };

  EXPECT_EQ(ValidateHeader(MakeHeader(min_params, kMinChunkSizeLog2)), HeaderStatus::kOk);
  EXPECT_EQ(ValidateHeader(MakeHeader(max_params, kMaxChunkSizeLog2)), HeaderStatus::kOk);
}

/**
 * @brief   Verify a chunk size outside the accepted range is rejected
 */
TEST_F(FileHeaderTest, RejectsOutOfRangeChunkSize) {
  const std::array<uint8_t, 2> cases{ kMinChunkSizeLog2 - 1, kMaxChunkSizeLog2 + 1 };

  for (uint8_t chunk_log2 : cases) {
    SCOPED_TRACE(testing::Message() << "chunk_log2=" << static_cast<int>(chunk_log2));

    EXPECT_EQ(ValidateHeader(MakeHeader({}, chunk_log2)), HeaderStatus::kBadChunkSize);
  }
}

/**
 * @brief   Verify a parameter just outside the accepted range is rejected
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

    EXPECT_EQ(ValidateHeader(MakeHeader(params)), HeaderStatus::kBadParams);
  }
}

/**
 * @brief   Verify the chunk size is reported when a header is wrong in more than one way
 */
TEST_F(FileHeaderTest, ReportsChunkSizeBeforeParams) {
  const KdfParams params{ .time_cost = kMaxTimeCost + 1, .mem_cost = kMaxMemCost + 1, .parallelism = 0 };

  EXPECT_EQ(ValidateHeader(MakeHeader(params, kMaxChunkSizeLog2 + 1)), HeaderStatus::kBadChunkSize);
}

/**
 * @brief   Verify reading applies validation, so a caller never sees an out-of-range header
 */
TEST_F(FileHeaderTest, ReadRejectsOutOfRangeHeader) {
  const KdfParams params{ .time_cost = kMaxTimeCost + 1, .mem_cost = kMaxMemCost + 1, .parallelism = 0 };
  FileHeader header;

  Store(MakeHeader(params));

  EXPECT_EQ(Reload(header), HeaderStatus::kBadParams);

  Store(MakeHeader({}, kMinChunkSizeLog2 - 1));

  EXPECT_EQ(Reload(header), HeaderStatus::kBadChunkSize);
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
  const std::string bad_chunk = HeaderErrorMessage(HeaderStatus::kBadChunkSize);
  const std::string bad_params = HeaderErrorMessage(HeaderStatus::kBadParams);

  EXPECT_FALSE(read_error.empty());
  EXPECT_FALSE(bad_magic.empty());
  EXPECT_FALSE(bad_chunk.empty());
  EXPECT_FALSE(bad_params.empty());

  EXPECT_NE(bad_chunk, read_error);
  EXPECT_NE(bad_chunk, bad_magic);
  EXPECT_NE(bad_chunk, bad_params);
  EXPECT_NE(read_error, bad_magic);
  EXPECT_NE(read_error, bad_params);
  EXPECT_NE(bad_magic, bad_params);

  EXPECT_STREQ(HeaderErrorMessage(HeaderStatus::kOk), "");
}
