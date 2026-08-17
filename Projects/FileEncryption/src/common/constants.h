/**
 * @file	constants.h
 * @brief	Header file for constants
 * @author	Astatine387
 */

#pragma once

#include <cstddef>
#include <cstdint>

inline constexpr double kFontScale = 1.2;  /// GUI font scale

inline constexpr size_t kKeySize = 32;            /// AES-GCM key size in bytes
inline constexpr size_t kSaltSize = 16;           /// Argon2id salt size in bytes
inline constexpr uint32_t kMemCost = 512 * 1024;  /// Argon2id memory cost in KiB
inline constexpr uint32_t kTimeCost = 4;          /// Argon2id time cost
inline constexpr uint32_t kParallelism = 4;       /// Argon2id parallelism

/* Accepted range for the parameters stored in a file header */

inline constexpr uint32_t kMinMemCost = 64 * 1024;    /// Minimum accepted Argon2id memory cost in KiB
inline constexpr uint32_t kMaxMemCost = 4096 * 1024;  /// Maximum accepted Argon2id memory cost in KiB
inline constexpr uint32_t kMinTimeCost = 1;           /// Minimum accepted Argon2id time cost
inline constexpr uint32_t kMaxTimeCost = 16;          /// Maximum accepted Argon2id time cost
inline constexpr uint32_t kMinParallelism = 1;        /// Minimum accepted Argon2id parallelism
inline constexpr uint32_t kMaxParallelism = 16;       /// Maximum accepted Argon2id parallelism

/* A default outside the accepted range would produce files this build cannot decrypt */

static_assert(kMemCost >= kMinMemCost && kMemCost <= kMaxMemCost, "Default memory cost is out of range");
static_assert(kTimeCost >= kMinTimeCost && kTimeCost <= kMaxTimeCost, "Default time cost is out of range");
static_assert(kParallelism >= kMinParallelism && kParallelism <= kMaxParallelism,
              "Default parallelism is out of range");

inline constexpr size_t kBlockSize = 16;   /// AES-GCM block size in bytes
inline constexpr size_t kBuffSize = 4096;  /// Buffer size in blocks
inline constexpr size_t kIVSize = 12;      /// Initial vector size in bytes
inline constexpr size_t kTagSize = 16;     /// Authentication tag size in bytes
inline constexpr size_t kBuffNum = 2;      /// Number of buffers for swapping

inline constexpr size_t kMagicSize = 4;                         /// Magic number size
inline constexpr uint32_t kMagicNum = 0xe07bca75;               /// Magic number to distinguish encrypted file
inline constexpr size_t kKdfSize = 3 * sizeof(uint32_t);        /// Argon2id parameter block size in bytes
inline constexpr size_t kKdfParamSize = kMagicSize + kKdfSize;  /// Header bytes preceding the salt

inline constexpr size_t kDataOffset = kKdfParamSize + kSaltSize + kIVSize;  /// Plaintext header size in bytes

inline constexpr int64_t kMaxSize = 64ULL * 1024 * 1024 * 1024 - 32;  /// Maximum source file size that can be processed
inline constexpr int64_t kMinSize = static_cast<int64_t>(kDataOffset + kTagSize);  /// Minimum encrypted file size

enum class CryptoMode : std::uint8_t {
  kEncrypt,
  kDecrypt,
};

/**
 * @enum	Result
 * @brief	Generic success/failure outcome of an operation
 */
enum class Result : std::uint8_t {
  kSuccess,
  kFailure,
};
