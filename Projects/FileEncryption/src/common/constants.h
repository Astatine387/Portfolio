/**
 * @file	constants.h
 * @brief	Header file for constants
 * @author	Astatine387
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

inline constexpr double kFontScale = 1.2;  /// GUI font scale

inline constexpr size_t kKeySize = 32;            /// AES-GCM key size in bytes
inline constexpr size_t kSaltSize = 16;           /// Argon2id salt size in bytes
inline constexpr uint32_t kMemCost = 512 * 1024;  /// Argon2id memory cost in KiB
inline constexpr uint32_t kTimeCost = 4;          /// Argon2id time cost
inline constexpr uint32_t kParallelism = 4;       /// Argon2id parallelism

/* Accepted range for the parameters stored in a file header. Wider than the defaults above on purpose:
 * the defaults are only what this build writes, while the range is what it agrees to read, so a file
 * written with other parameters still opens. */

inline constexpr uint32_t kMinMemCost = 64 * 1024;    /// Minimum accepted Argon2id memory cost in KiB
inline constexpr uint32_t kMaxMemCost = 4096 * 1024;  /// Maximum accepted Argon2id memory cost in KiB
inline constexpr uint32_t kMinTimeCost = 1;           /// Minimum accepted Argon2id time cost
inline constexpr uint32_t kMaxTimeCost = 16;          /// Maximum accepted Argon2id time cost
inline constexpr uint32_t kMinParallelism = 1;        /// Minimum accepted Argon2id parallelism
inline constexpr uint32_t kMaxParallelism = 16;       /// Maximum accepted Argon2id parallelism

static_assert(kMemCost >= kMinMemCost && kMemCost <= kMaxMemCost, "Default memory cost is out of range");
static_assert(kTimeCost >= kMinTimeCost && kTimeCost <= kMaxTimeCost, "Default time cost is out of range");
static_assert(kParallelism >= kMinParallelism && kParallelism <= kMaxParallelism,
              "Default parallelism is out of range");

/* Every chunk costs a tag on the disk and a nonce re-initialization in the cipher, while two buffers of
 * this size are held for the whole run, so the size trades file overhead against memory. It is recorded
 * per file, which is what lets the accepted range be wider than the one value this build writes. */

inline constexpr uint8_t kChunkSizeLog2 = 16;     /// Base-2 logarithm of the chunk size this build writes (64 KiB)
inline constexpr uint8_t kMinChunkSizeLog2 = 12;  /// Minimum accepted chunk size logarithm (4 KiB)
inline constexpr uint8_t kMaxChunkSizeLog2 = 20;  /// Maximum accepted chunk size logarithm (1 MiB)
inline constexpr size_t kChunkSize = size_t{ 1 } << kChunkSizeLog2;  /// Chunk size this build writes, in bytes

static_assert(kChunkSizeLog2 >= kMinChunkSizeLog2 && kChunkSizeLog2 <= kMaxChunkSizeLog2,
              "Default chunk size is out of range");

/* Encrypted file format */

inline constexpr std::array<uint8_t, 4> kMagic = { 0xE0, 0x7B, 0xCA, 0x75 };  /// Magic number of the format

inline constexpr size_t kMagicSize = 4;    /// Magic number size in bytes
inline constexpr size_t kHeaderSize = 33;  /// Plaintext header size in bytes
inline constexpr size_t kNonceSize = 12;   /// AES-GCM nonce size in bytes
inline constexpr size_t kTagSize = 16;     /// Authentication tag size in bytes
inline constexpr size_t kBlockSize = 16;   /// AES block size in bytes

/* A header and one chunk: an empty plaintext still produces a final chunk, and that chunk still carries
 * a tag, so nothing shorter than this can be a file of this format */

inline constexpr size_t kMinSize = kHeaderSize + kTagSize;  /// Minimum encrypted file size

/* Two, because the pipeline keeps exactly one chunk in flight: one buffer is being written while the
 * next is being filled */

inline constexpr size_t kBuffNum = 2;  /// Number of buffers for swapping

/* The format carries no version field, so a change of layout is a change of magic value */

static_assert(kMagic.size() == kMagicSize, "Magic number size does not match the magic value");

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
