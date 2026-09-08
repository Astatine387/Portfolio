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
inline constexpr size_t kCommitSize = 32;         /// Key commitment size in bytes
inline constexpr size_t kSaltSize = 16;           /// Argon2id salt size in bytes
inline constexpr uint32_t kMemCost = 512 * 1024;  /// Argon2id memory cost in KiB
inline constexpr uint32_t kTimeCost = 4;          /// Argon2id time cost
inline constexpr uint32_t kParallelism = 4;       /// Argon2id parallelism

/* AES-GCM authenticates a chunk without committing to the key it was verified under, so a crafted file
 * can be made to authenticate under two passwords at once. The commitment is what settles which password
 * a file belongs to, and it comes out of the same derivation as the key rather than out of a second
 * Argon2id call, so anchoring the password costs nothing on top of a derivation that already runs.
 *
 * Splitting one derivation this way holds only while the whole of it is a single BLAKE2b call. Argon2's
 * variable-length hash H' is exactly that for an output of 64 bytes or less, so the two halves are two
 * halves of one PRF output, and the commitment can sit in a plaintext header without saying anything
 * about the key beside it. Past 64 bytes H' becomes a chain of 64-byte blocks, each hashed from the one
 * before it, so the published half would be computed from the block the key was cut out of and the two
 * would no longer be independent. Nothing about crossing that line is visible: the build succeeds, the
 * tests pass, and only the argument is gone, which is why the size is asserted rather than left to this
 * comment. More derived material than this takes a second derivation, not a longer output. */

inline constexpr size_t kDerivedSize = kKeySize + kCommitSize;  /// Bytes one Argon2id derivation produces

static_assert(kDerivedSize <= 64,
              "Derived output is longer than one BLAKE2b call, so Argon2's H' chains and the commitment no longer "
              "splits cleanly from the key");

/* Accepted range for the parameters stored in a file header. Wider than the defaults above on purpose:
 * the defaults are only what this build writes, while the range is what it agrees to read, so a file
 * written with other parameters still opens. */

inline constexpr uint32_t kMinMemCost = 64 * 1024;    /// Minimum accepted Argon2id memory cost in KiB
inline constexpr uint32_t kMaxMemCost = 2048 * 1024;  /// Maximum accepted Argon2id memory cost in KiB
inline constexpr uint32_t kMinTimeCost = 1;           /// Minimum accepted Argon2id time cost
inline constexpr uint32_t kMaxTimeCost = 8;          /// Maximum accepted Argon2id time cost
inline constexpr uint32_t kMinParallelism = 1;        /// Minimum accepted Argon2id parallelism
inline constexpr uint32_t kMaxParallelism = 8;       /// Maximum accepted Argon2id parallelism

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
inline constexpr size_t kHeaderSize = 65;  /// Plaintext header size in bytes
inline constexpr size_t kNonceSize = 12;   /// AES-GCM nonce size in bytes
inline constexpr size_t kTagSize = 16;     /// Authentication tag size in bytes
inline constexpr size_t kBlockSize = 16;   /// AES block size in bytes

/* A header and one chunk: an empty plaintext still produces a final chunk, and that chunk still carries
 * a tag, so nothing shorter than this can be a file of this format */

inline constexpr size_t kMinSize = kHeaderSize + kTagSize;  /// Minimum encrypted file size

/* GCM's proof treats the block cipher as a function while AES is a permutation, and closing that gap
 * costs sigma^2 / 2^128 over the 128-bit blocks processed under one key. Holding that at 2^-32, the
 * probability SP 800-38D 8 already treats as negligible, allows 2^48 blocks, and this is the nearest
 * power of two below it. A chunk adds six GHASH blocks of its own for the header and the length block,
 * which is 0.15% at the default chunk size, so the bound is about bytes rather than about chunks.
 *
 * Every file draws a fresh salt and derives its own key from it, so this is spent per file and nothing
 * accumulates across a session.
 *
 * It bounds what to produce, not what to accept. Encryption refuses a source above it; decryption does
 * not test it, because the blocks of a file that already exists have already been processed and turning
 * it away recovers nothing while costing the file. A ciphertext also carries a tag per chunk, so this
 * same value on a decryption would reject a file this build had just written at its own ceiling. */

inline constexpr int64_t kMaxPlaintextSize = int64_t{ 1 } << 52;  /// Largest plaintext this build encrypts (4 PiB)

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

/**
 * @enum	WorkPhase
 * @brief	Stage a run has reached
 *
 * A run is not one long cancellable stretch. Argon2id cannot be taken back out once it is inside, and
 * the flush after the last chunk must not be, because the output is complete by then and a cancel would
 * only throw away finished work. Only the chunk loop between the two polls the flag, so the phase is
 * what tells an interface whether asking to cancel would mean anything.
 */
enum class WorkPhase : std::uint8_t {
  kDerivingKey,  /// Argon2id is running and cannot be interrupted
  kProcessing,   /// Chunk loop, where the cancellation flag is polled between chunks
  kFinishing,    /// Flush and publish, where the output is already complete
};

/**
 * @brief	Whether the cancellation flag can still end a run during this phase
 * @param	phase	Phase to ask about
 * @return	true if raising the flag now would end the run early
 *
 * Kept beside the enum rather than in the interface, so the answer comes from the layer that actually
 * polls the flag rather than from whatever the window happens to believe.
 */
[[nodiscard]] constexpr bool IsCancellablePhase(WorkPhase phase) {
  return phase == WorkPhase::kProcessing;
}
