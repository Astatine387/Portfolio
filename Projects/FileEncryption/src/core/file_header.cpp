/**
 * @file	file_header.cpp
 * @brief	Implementation of encrypted file header handling
 * @author	Astatine387
 */

#include "core/file_header.h"

#include <cstring>

#include "utils/platform.h"

HeaderStatus ReadHeader(FILE* file, FileHeader& header) {
  std::array<uint8_t, kDataOffset> buff{};

  if (Seek(file, 0, SEEK_SET) == Result::kFailure) {
    return HeaderStatus::kReadError;  // LCOV_EXCL_LINE
  }

  if (fread(buff.data(), sizeof(uint8_t), buff.size(), file) != buff.size()) {
    return HeaderStatus::kReadError;
  }

  /* Reject a foreign file before anything else in the header is trusted */

  uint32_t magic = 0;

  memcpy(&magic, buff.data(), kMagicSize);

  if (magic != kMagicNum) {
    return HeaderStatus::kBadMagic;
  }

  memcpy(&header.params.time_cost, buff.data() + kMagicSize, sizeof(uint32_t));
  memcpy(&header.params.mem_cost, buff.data() + kMagicSize + sizeof(uint32_t), sizeof(uint32_t));
  memcpy(&header.params.parallelism, buff.data() + kMagicSize + 2 * sizeof(uint32_t), sizeof(uint32_t));

  memcpy(header.salt.data(), buff.data() + kKdfParamSize, kSaltSize);
  memcpy(header.iv.data(), buff.data() + kKdfParamSize + kSaltSize, kIVSize);

  return HeaderStatus::kOk;
}

Result WriteHeader(FILE* file, const FileHeader& header) {
  std::array<uint8_t, kDataOffset> buff{};

  memcpy(buff.data(), &kMagicNum, kMagicSize);

  memcpy(buff.data() + kMagicSize, &header.params.time_cost, sizeof(uint32_t));
  memcpy(buff.data() + kMagicSize + sizeof(uint32_t), &header.params.mem_cost, sizeof(uint32_t));
  memcpy(buff.data() + kMagicSize + 2 * sizeof(uint32_t), &header.params.parallelism, sizeof(uint32_t));

  memcpy(buff.data() + kKdfParamSize, header.salt.data(), kSaltSize);
  memcpy(buff.data() + kKdfParamSize + kSaltSize, header.iv.data(), kIVSize);

  if (fwrite(buff.data(), sizeof(uint8_t), buff.size(), file) != buff.size()) {
    return Result::kFailure;  // LCOV_EXCL_LINE
  }

  return Result::kSuccess;
}

HeaderStatus ValidateKdfParams(const KdfParams& params) {
  if (params.time_cost < kMinTimeCost || params.time_cost > kMaxTimeCost) {
    return HeaderStatus::kBadParams;
  }

  if (params.mem_cost < kMinMemCost || params.mem_cost > kMaxMemCost) {
    return HeaderStatus::kBadParams;
  }

  if (params.parallelism < kMinParallelism || params.parallelism > kMaxParallelism) {
    return HeaderStatus::kBadParams;
  }

  return HeaderStatus::kOk;
}

const char* HeaderErrorMessage(HeaderStatus status) {
  switch (status) {
    case HeaderStatus::kReadError:
      return "[File] Read failed - Cannot read the file header\n";

    case HeaderStatus::kBadMagic:
      return "[File] Validation failed - Not a FileEncryption file\n";

    case HeaderStatus::kBadParams:
      return "[File] Validation failed - Unsupported key derivation parameters\n";

    case HeaderStatus::kOk:
      break;
  }

  return "";
}
