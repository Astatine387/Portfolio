/**
 * @file	vault_header.cpp
 * @brief	Implementation of the plaintext vault header
 * @author	Astatine387
 */

#include "core/vault_header.h"

#include <algorithm>

#include "utils/byte_order.h"

namespace {

/* Each offset is stated relative to the one before it, so a field can only be inserted by moving every field after
 * it, and the assert below refuses a layout that no longer fills the header exactly */

constexpr size_t kVersionOffset = kMagicSize;                             // 4
constexpr size_t kTimeCostOffset = kVersionOffset + kVersionSize;         // 5
constexpr size_t kMemCostOffset = kTimeCostOffset + sizeof(uint32_t);     // 9
constexpr size_t kParallelismOffset = kMemCostOffset + sizeof(uint32_t);  // 13
constexpr size_t kSaltOffset = kParallelismOffset + sizeof(uint32_t);     // 17
constexpr size_t kCommitOffset = kSaltOffset + kSaltSize;                 // 33

static_assert(kCommitOffset + kCommitSize == kHeaderSize, "Header field offsets do not fill the header");

}  // namespace

void SerializeHeader(std::span<uint8_t, kHeaderSize> dst, const VaultHeader& header) {
  /* These bytes are both the header on the disk and the associated data of the GCM pass over the vault, so the layout
   * is part of the format: moving a field changes what the tag of every existing vault covers */

  StoreLE32(dst.data(), kMagicNum);

  dst[kVersionOffset] = kFormatVersion;

  StoreLE32(dst.data() + kTimeCostOffset, header.params.time_cost);
  StoreLE32(dst.data() + kMemCostOffset, header.params.mem_cost);
  StoreLE32(dst.data() + kParallelismOffset, header.params.parallelism);

  std::ranges::copy(header.salt, dst.begin() + kSaltOffset);
  std::ranges::copy(header.commitment, dst.begin() + kCommitOffset);
}

HeaderStatus ParseHeader(std::span<const uint8_t> src, VaultHeader& header) {
  if (src.size() < kHeaderSize) {
    return HeaderStatus::kTooSmall;
  }

  /* Check whether the file was written by this program, and say so plainly when it was written by the build before
   * the commitment existed: that vault is readable in principle but not by this format, which is a different thing
   * to tell a user than a file that was never a vault */

  const uint32_t magic = LoadLE32(src.data());

  if (magic == kLegacyMagicNum) {
    return HeaderStatus::kLegacyFormat;
  }

  if (magic != kMagicNum) {
    return HeaderStatus::kBadMagic;
  }

  if (src[kVersionOffset] != kFormatVersion) {
    return HeaderStatus::kBadVersion;
  }

  VaultHeader parsed;

  parsed.params.time_cost = LoadLE32(src.data() + kTimeCostOffset);
  parsed.params.mem_cost = LoadLE32(src.data() + kMemCostOffset);
  parsed.params.parallelism = LoadLE32(src.data() + kParallelismOffset);

  std::ranges::copy(src.subspan(kSaltOffset, kSaltSize), parsed.salt.begin());
  std::ranges::copy(src.subspan(kCommitOffset, kCommitSize), parsed.commitment.begin());

  /* Hand back nothing the caller would still have to range-check */

  const HeaderStatus status = ValidateHeader(parsed);

  if (status != HeaderStatus::kOk) {
    return status;
  }

  header = parsed;

  return HeaderStatus::kOk;
}

HeaderStatus ValidateHeader(const VaultHeader& header) {
  /* A header is whatever the file happened to contain, and it is read before the password is ever tried. mem_cost is
   * an Argon2id allocation in KiB and the other two multiply the work done over it, so these bounds are the only
   * thing standing between a crafted vault and the cost it asks this machine to pay before any tag is checked.
   *
   * The commitment is absent from this for a reason: every value of it is structurally valid, and which one is right
   * is settled by comparing it against a derivation rather than by any range. */

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

const char* HeaderErrorMessage(HeaderStatus status) {
  switch (status) {
    case HeaderStatus::kTooSmall:
      return "[File] Validation failed - File is too small to be a valid vault\n";

    case HeaderStatus::kBadMagic:
      return "[File] Validation failed - Not a vault file\n";

    case HeaderStatus::kLegacyFormat:
      return "[File] Validation failed - Vault predates the current format and cannot be opened\n";

    case HeaderStatus::kBadVersion:
      return "[File] Validation failed - Unsupported vault format version\n";

    case HeaderStatus::kBadParams:
      return "[File] Validation failed - Unsupported key derivation parameters\n";

    case HeaderStatus::kOk:
      break;
  }

  return "";
}
