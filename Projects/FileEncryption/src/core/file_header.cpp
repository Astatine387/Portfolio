/**
 * @file    file_header.cpp
 * @brief   Implementation of encrypted file header
 * @author	Astatine387
 */

#include "core/file_header.h"

#include <algorithm>

#include "utils/byte_order.h"
#include "utils/platform.h"

namespace {

/* Each offset is stated relative to the one before it, so a field can only be inserted by moving every
 * field after it, and the assert below refuses a layout that no longer fills the header exactly */

constexpr size_t kChunkLog2Offset = kMagicSize;            // 4
constexpr size_t kTimeCostOffset = kChunkLog2Offset + 1;   // 5
constexpr size_t kMemCostOffset = kTimeCostOffset + 4;     // 9
constexpr size_t kParallelismOffset = kMemCostOffset + 4;  // 13
constexpr size_t kSaltOffset = kParallelismOffset + 4;     // 17

static_assert(kSaltOffset + kSaltSize == kHeaderSize, "Header field offsets do not fill the header");

}  // namespace

void SerializeHeader(std::span<uint8_t, kHeaderSize> dst, const FileHeader& header) {
  /* These bytes are both the header on the disk and the associated data of every chunk, so the layout is
   * part of the format: moving a field changes what every tag in every existing file covers */

  std::ranges::copy(kMagic, dst.begin());

  dst[kChunkLog2Offset] = header.chunk_log2;

  StoreLE32(dst.data() + kTimeCostOffset, header.params.time_cost);
  StoreLE32(dst.data() + kMemCostOffset, header.params.mem_cost);
  StoreLE32(dst.data() + kParallelismOffset, header.params.parallelism);

  std::ranges::copy(header.salt, dst.begin() + kSaltOffset);
}

HeaderStatus ReadHeader(FILE* file, FileHeader& header) {
  std::array<uint8_t, kHeaderSize> buff{};

  if (Seek(file, 0, SEEK_SET) == Result::kFailure) {
    return HeaderStatus::kReadError;  // LCOV_EXCL_LINE
  }

  if (fread(buff.data(), sizeof(uint8_t), buff.size(), file) != buff.size()) {
    return HeaderStatus::kReadError;
  }

  /* Check whether the file is encrypted by this program */

  if (!std::ranges::equal(kMagic, std::span(buff).first(kMagicSize))) {
    return HeaderStatus::kBadMagic;
  }

  FileHeader parsed;

  parsed.chunk_log2 = buff[kChunkLog2Offset];

  parsed.params.time_cost = LoadLE32(buff.data() + kTimeCostOffset);
  parsed.params.mem_cost = LoadLE32(buff.data() + kMemCostOffset);
  parsed.params.parallelism = LoadLE32(buff.data() + kParallelismOffset);

  std::ranges::copy(std::span(buff).subspan(kSaltOffset, kSaltSize), parsed.salt.begin());

  /* Hand back nothing the caller would still have to range-check */

  const HeaderStatus status = ValidateHeader(parsed);

  if (status != HeaderStatus::kOk) {
    return status;
  }

  header = parsed;

  return HeaderStatus::kOk;
}

HeaderStatus ValidateHeader(const FileHeader& header) {
  /* A header is whatever the file happened to contain, and it is read before the password is ever tried.
   * chunk_log2 is used as a shift width and sizes both chunk buffers, so an unchecked value is undefined
   * behaviour before it is an allocation; mem_cost is an Argon2id allocation in KiB, so an unchecked one
   * lets a crafted file ask for terabytes. */

  if (header.chunk_log2 < kMinChunkSizeLog2 || kMaxChunkSizeLog2 < header.chunk_log2) {
    return HeaderStatus::kBadChunkSize;
  }

  if (header.params.time_cost < kMinTimeCost || kMaxTimeCost < header.params.time_cost) {
    return HeaderStatus::kBadParams;
  }

  if (header.params.mem_cost < kMinMemCost || kMaxMemCost < header.params.mem_cost) {
    return HeaderStatus::kBadParams;
  }

  if (header.params.parallelism < kMinParallelism || kMaxParallelism < header.params.parallelism) {
    return HeaderStatus::kBadParams;
  }

  return HeaderStatus::kOk;
}

Result WriteHeader(FILE* file, const FileHeader& header) {
  std::array<uint8_t, kHeaderSize> buff{};

  SerializeHeader(buff, header);

  if (fwrite(buff.data(), sizeof(uint8_t), buff.size(), file) != buff.size()) {
    return Result::kFailure;  // LCOV_EXCL_LINE
  }

  return Result::kSuccess;
}

const char* HeaderErrorMessage(HeaderStatus status) {
  switch (status) {
    case HeaderStatus::kReadError:
      return "[File] Read failed - Cannot read the file header\n";

    case HeaderStatus::kBadMagic:
      return "[File] Validation failed - Not a FileEncryption file\n";

    case HeaderStatus::kBadChunkSize:
      return "[File] Validation failed - Unsupported chunk size\n";

    case HeaderStatus::kBadParams:
      return "[File] Validation failed - Unsupported key derivation parameters\n";

    case HeaderStatus::kOk:
      break;
  }

  return "";
}
