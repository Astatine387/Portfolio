/**
 * @file    constants.h
 * @brief   Header file for constants
 * @author  Astatine387
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>

inline constexpr double kFontScale = 1.2;  /// GUI font scale

inline constexpr int kMaxMasterPwLen =
    256;                                   /// Maximum length of master password
inline constexpr size_t kKeySize = 32;     /// AES-GCM key size in bytes
inline constexpr size_t kCommitSize = 32;  /// Key commitment size in bytes

/* Argon2id parameters */

inline constexpr size_t kSaltSize = 16;           /// Salt size in bytes
inline constexpr uint32_t kMemCost = 512 * 1024;  /// Memory cost in KiB
inline constexpr uint32_t kTimeCost = 4;          /// Time cost
inline constexpr uint32_t kParallelism = 4;       /// Parallelism
inline constexpr size_t kDerivedSize =
    kKeySize + kCommitSize;  /// Output size in bytes

static_assert(kDerivedSize <= 64,
              "One derivation past 64 bytes puts Argon2's H' into chained "
              "blocks, and the commitment written to the "
              "vault header would then follow from the block the session key "
              "was taken from");

/* Accepted Argon2id parameter ranges */

inline constexpr uint32_t kMinMemCost =
    64 * 1024;  /// Minimum memory cost in KiB
inline constexpr uint32_t kMaxMemCost =
    2048 * 1024;                                /// Maximum memory cost in KiB
inline constexpr uint32_t kMinTimeCost = 1;     /// Minimum time cost
inline constexpr uint32_t kMaxTimeCost = 8;     /// Maximum time cost
inline constexpr uint32_t kMinParallelism = 1;  /// Minimum parallelism
inline constexpr uint32_t kMaxParallelism = 8;  /// Maximum parallelism

static_assert(kMemCost >= kMinMemCost && kMemCost <= kMaxMemCost,
              "Default memory cost is out of range");
static_assert(kTimeCost >= kMinTimeCost && kTimeCost <= kMaxTimeCost,
              "Default time cost is out of range");
static_assert(kParallelism >= kMinParallelism &&
                  kParallelism <= kMaxParallelism,
              "Default parallelism is out of range");

/* Vault file format */

inline constexpr size_t kBlockSize = 16;   /// AES-GCM block size in bytes
inline constexpr size_t kBuffSize = 4096;  /// Decryption chunk size in blocks
inline constexpr size_t kIVSize = 12;      /// Initial vector size in bytes
inline constexpr size_t kTagSize = 16;     /// Authentication tag size in bytes

inline constexpr int kMagicSize = 4;  /// Magic number size
inline constexpr uint32_t kMagicNum =
    0x9e2c74d1;  /// Magic number to distinguish vault file
inline constexpr uint32_t kLegacyMagicNum =
    0x63a5baf3;  /// Magic number of the pre-commitment format
inline constexpr uint8_t kFormatVersion = 1;  /// On-disk vault format version
inline constexpr size_t kVersionSize =
    1;  /// Format version field size in bytes
inline constexpr size_t kKdfSize =
    3 * sizeof(uint32_t);  /// Argon2id parameter block size in bytes
inline constexpr size_t kCountSize =
    sizeof(uint32_t);  /// Entry count field size

inline constexpr size_t kHeaderSize =
    kMagicSize + kVersionSize + kKdfSize + kSaltSize +
    kCommitSize;  /// Authenticated header bytes

/* Memory locking budget */

inline constexpr size_t kPageSize =
    4096;  /// Page size the locking arithmetic assumes
inline constexpr size_t kCanarySize =
    16;  /// Canary libsodium places ahead of a sodium_malloc region
inline constexpr size_t kLockBudget =
    8ULL * 1024 * 1024;  /// Locked memory one process is assumed to be granted
inline constexpr size_t kLockReserve =
    32 *
    kPageSize;  /// Budget held back for what is locked beside the two images

/**
 * @brief   Report what an allocation of a given size spends against the locking
 * budget
 * @param   size  Bytes asked of sodium_malloc
 * @return  Bytes sodium_malloc locks to satisfy the request
 */
constexpr size_t LockedBytes(size_t size) {
  return ((size + kCanarySize + kPageSize - 1) / kPageSize) * kPageSize;
}

/* Vault size limits */

inline constexpr int64_t kMaxSize = 4000LL * 1024;  /// Maximum vault file size
inline constexpr int64_t kMinSize = (kHeaderSize + kIVSize + kCountSize +
                                     kTagSize);  /// Minimum vault file size
inline constexpr size_t kFrameSize =
    kHeaderSize + kIVSize + kTagSize;  /// Vault file bytes outside the image

/* (max) keeps a max macro from windows.h out of the call */

inline constexpr int64_t kMaxImageSize =
    kMaxSize - static_cast<int64_t>(kFrameSize);  /// Largest image that fits

static_assert(kMaxImageSize <=
                  static_cast<int64_t>((std::numeric_limits<int>::max)()),
              "The largest image kMaxSize leaves room for goes through a "
              "single EVP_EncryptUpdate call, which takes "
              "its length as an int, so a ceiling past that reaches it as a "
              "negative length rather than an error");

/* Entry field limits */

inline constexpr int kMaxSiteLen = 256;  /// Maximum length of site name
inline constexpr int kMaxAccLen = 256;   /// Maximum length of account
inline constexpr int kMaxEntryPwLen =
    256;  /// Maximum stored length of entry password

static_assert(kMaxEntryPwLen <= kMaxMasterPwLen,
              "An entry password the parser accepts has to fit the Password "
              "buffer it is later copied into");

inline constexpr int kMaxGenPwLen =
    32;  /// Maximum value of the generator slider
inline constexpr int kMinGenPwLen =
    8;  /// Minimum value of the generator slider
inline constexpr int kDefaultGenPwLen =
    16;  /// Default value of the generator slider

static_assert(kMaxGenPwLen <= kMaxEntryPwLen,
              "The generator can produce a password the vault cannot store");

/* Every field holds at least one byte, which ValidateEntryFields enforces */

inline constexpr size_t kMinEntrySize =
    (sizeof(uint32_t) + 1) * 3;  /// Minimum serialized entry size
inline constexpr size_t kMaxEntrySize =
    (sizeof(uint32_t) * 3) + kMaxSiteLen + kMaxAccLen +
    kMaxEntryPwLen;  /// Maximum serialized entry size

static_assert(
    LockedBytes(static_cast<size_t>(kMaxImageSize)) +
            LockedBytes(static_cast<size_t>(kMaxImageSize) + kMaxEntrySize) +
            kLockReserve <=
        kLockBudget,
    "The installed image and the candidate one entry above it no longer fit "
    "the locking budget together, "
    "which leaves the candidate swappable with every entry password in it");

/**
 * @brief   Create a new vault or open an existing one
 */
enum class VaultAction : std::uint8_t {
  kCreate,
  kOpen,
};

/**
 * @brief   Generic success/failure outcome
 */
enum class Result : std::uint8_t {
  kSuccess,
  kFailure,
};
