/**
 * @file    constants.h
 * @brief   Header file for constants
 * @author  Astatine387
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

inline constexpr double kFontScale = 1.2;  /// GUI font scale
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
              "Derived output is longer than one BLAKE2b call, so Argon2's H' "
              "chains and the commitment no longer "
              "splits cleanly from the key");

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

/* Chunk size */

inline constexpr uint8_t kChunkSizeLog2 =
    16;  /// Base-2 log of chunk size (64 KiB)
inline constexpr uint8_t kMinChunkSizeLog2 =
    12;  /// Base-2 log of minimum chunk size (4 KiB)
inline constexpr uint8_t kMaxChunkSizeLog2 =
    20;  /// Base-2 log of maximum chunk size (1 MiB)
inline constexpr size_t kChunkSize =
    size_t{ 1 } << kChunkSizeLog2;  /// Chunk size this build uses, in bytes

static_assert(kChunkSizeLog2 >= kMinChunkSizeLog2 &&
                  kChunkSizeLog2 <= kMaxChunkSizeLog2,
              "Default chunk size is out of range");

/* Encrypted file format */

inline constexpr std::array<uint8_t, 4> kMagic = { 0xE0, 0x7B, 0xCA,
                                                   0x75 };  /// Magic number

inline constexpr size_t kMagicSize = 4;    /// Magic number size in bytes
inline constexpr size_t kHeaderSize = 65;  /// Header size in bytes
inline constexpr size_t kNonceSize = 12;   /// AES-GCM nonce size in bytes
inline constexpr size_t kTagSize = 16;     /// Authentication tag size in bytes
inline constexpr size_t kBlockSize = 16;   /// AES block size in bytes

inline constexpr size_t kMinEncryptedSize =
    kHeaderSize + kTagSize;  /// Minimum encrypted file size
inline constexpr int64_t kMaxPlaintextSize =
    int64_t{ 1 } << 52;  /// Maximum plaintext file size (4 PiB)

inline constexpr size_t kBuffNum = 2;  /// Number of buffers for swapping

static_assert(kMagic.size() == kMagicSize,
              "Magic number size does not match the magic value");

/**
 * @brief   Encryption or decryption
 */
enum class CryptoMode : std::uint8_t {
  kEncrypt,
  kDecrypt,
};

/**
 * @brief   Generic success/failure outcome
 */
enum class Result : std::uint8_t {
  kSuccess,
  kFailure,
};

/**
 * @brief   Stage a run has reached
 */
enum class WorkPhase : std::uint8_t {
  kDerivingKey,  /// Argon2id is running
  kProcessing,   /// Chunk loop
  kFinishing,    /// Flush and publish, output is complete
};

/**
 * @brief   Whether the cancellation flag can still end a run during this phase
 * @param   phase   Phase to ask about
 * @return  true if raising the flag now would end the run early
 */
[[nodiscard]] constexpr bool IsCancellablePhase(WorkPhase phase) {
  return phase == WorkPhase::kProcessing;
}
