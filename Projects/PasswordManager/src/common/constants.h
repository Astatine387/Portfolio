/**
 * @file	constants.h
 * @brief	Header file for constants
 * @author	Astatine387
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>

inline constexpr double kFontScale = 1.2;  /// GUI font scale

inline constexpr int kMaxMasterPwLen = 256;       /// Maximum length of master password
inline constexpr size_t kKeySize = 32;            /// AES-GCM key size in bytes
inline constexpr size_t kCommitSize = 32;         /// Key commitment size in bytes
inline constexpr size_t kSaltSize = 16;           /// Argon2id salt size in bytes
inline constexpr uint32_t kMemCost = 512 * 1024;  /// Argon2id memory cost in KiB
inline constexpr uint32_t kTimeCost = 4;          /// Argon2id time cost
inline constexpr uint32_t kParallelism = 4;       /// Argon2id parallelism

/* AES-GCM authenticates a vault without committing to the key it was verified under, so a failing tag says only that
 * this key did not open this file and never which of the two was at fault. That is the whole of what a user is told
 * today when a vault refuses to open. The commitment settles it: it is derived beside the key, stored in the header
 * and compared before a single ciphertext byte is touched, so a mismatch names the password and a tag failure after
 * it names the file. It falls out of the derivation that already runs, so the distinction costs no second Argon2id
 * pass.
 *
 * Splitting one derivation this way holds only while the whole of it is a single BLAKE2b call. Argon2's
 * variable-length hash H' is exactly that for an output of 64 bytes or less, so the key and the commitment are two
 * halves of one PRF output and the published half says nothing about the half beside it. Past 64 bytes H' becomes a
 * chain of 64-byte blocks, each hashed from the one before it, and the commitment in the plaintext header would then
 * follow from the block the session key was cut out of. Crossing that line shows up in nothing a build or a test run
 * would report, which is why the bound is asserted rather than left to this comment. More derived material than this
 * takes a second derivation, not a longer output. */

inline constexpr size_t kDerivedSize = kKeySize + kCommitSize;  /// Bytes one Argon2id derivation produces

static_assert(kDerivedSize <= 64,
              "One derivation past 64 bytes puts Argon2's H' into chained blocks, and the commitment written to the "
              "vault header would then follow from the block the session key was taken from");

/* Accepted range for the parameters stored in a vault header. Wider than the defaults above on purpose: the defaults
 * are only what this build writes, while the range is what it agrees to read, so a vault written under other
 * parameters still opens.
 *
 * The ceilings are not a matter of taste. A header is read and its parameters are spent before the tag is checked,
 * which is the one part of opening a vault that an attacker who hands over a file gets to choose the cost of. The
 * key commitment does not help here and neither does authenticating the header, since both are things that happen
 * after the derivation they would have to precede. Only these bounds do, so they are set at what this build could
 * plausibly have written rather than at what Argon2id will accept: 4 GiB by 16 iterations by 16 lanes was a machine
 * taken out of service by a file, and no vault has ever been written above 512 MiB by 4 by 4. */

inline constexpr uint32_t kMinMemCost = 64 * 1024;    /// Minimum accepted Argon2id memory cost in KiB
inline constexpr uint32_t kMaxMemCost = 2048 * 1024;  /// Maximum accepted Argon2id memory cost in KiB
inline constexpr uint32_t kMinTimeCost = 1;           /// Minimum accepted Argon2id time cost
inline constexpr uint32_t kMaxTimeCost = 8;           /// Maximum accepted Argon2id time cost
inline constexpr uint32_t kMinParallelism = 1;        /// Minimum accepted Argon2id parallelism
inline constexpr uint32_t kMaxParallelism = 8;        /// Maximum accepted Argon2id parallelism

/* A default outside the accepted range would produce vaults this build cannot reopen */

static_assert(kMemCost >= kMinMemCost && kMemCost <= kMaxMemCost, "Default memory cost is out of range");
static_assert(kTimeCost >= kMinTimeCost && kTimeCost <= kMaxTimeCost, "Default time cost is out of range");
static_assert(kParallelism >= kMinParallelism && kParallelism <= kMaxParallelism,
              "Default parallelism is out of range");

inline constexpr size_t kBlockSize = 16;   /// AES-GCM block size in bytes
inline constexpr size_t kBuffSize = 4096;  /// Decryption chunk size in blocks
inline constexpr size_t kIVSize = 12;      /// Initial vector size in bytes
inline constexpr size_t kTagSize = 16;     /// Authentication tag size in bytes

inline constexpr int kMagicSize = 4;                      /// Magic number size
inline constexpr uint32_t kMagicNum = 0x9e2c74d1;         /// Magic number to distinguish vault file
inline constexpr uint32_t kLegacyMagicNum = 0x63a5baf3;   /// Magic number of the pre-commitment format
inline constexpr uint8_t kFormatVersion = 1;              /// On-disk vault format version
inline constexpr size_t kVersionSize = 1;                 /// Format version field size in bytes
inline constexpr size_t kKdfSize = 3 * sizeof(uint32_t);  /// Argon2id parameter block size in bytes
inline constexpr size_t kCountSize = sizeof(uint32_t);    /// Entry count field size

/* Everything a vault file states in the clear, and every byte of it the associated data of the one GCM pass that
 * follows. The salt and the parameters were already bound to the ciphertext by the derivation they feed, but the
 * commitment is not, and a header field added later would not be either unless it were named here. */

inline constexpr size_t kHeaderSize =
    kMagicSize + kVersionSize + kKdfSize + kSaltSize + kCommitSize;  /// Authenticated header bytes

/* A vault is never streamed. The whole of it is decrypted into sodium_malloc memory and held there for as long as it
 * stays open, beside an ordinary heap copy of the ciphertext of the same size, so this ceiling is in the end a claim
 * about how much memory one process can lock. Nothing enforces it while running: sodium_malloc does not report a
 * refused mlock, it hands back a perfectly good pointer and leaves the pages swappable, so a vault over the limit
 * does not fail to open. It opens with its plaintext no longer pinned and says nothing about it. There is no error to
 * catch, which is why this is a constant chosen to sit under the limit rather than a check written against it.
 *
 * A systemd default grants 8 MiB, soft and hard alike, so raising the soft limit to the hard one at startup gains
 * nothing on such a machine, and libsodium locks a page of its own beyond what was asked for, which leaves a single
 * allocation under 8 MiB less a page if it is to be locked at all. Four MiB clears that with the master password and
 * the session key locked beside it. Two GiB cleared nothing, being 256 times the whole limit, and any vault written
 * near that old ceiling would have opened unpinned.
 *
 * Little is given up for the smaller figure. The largest entry the parser will accept is 780 bytes, 256 of site and
 * 256 of account and 256 of password beside the three 4-byte length fields, and 5,377 of those fit under 4 MiB once
 * the header, IV, entry count and tag are paid for. Entries of the length a person actually types run nearer 60
 * bytes, which is some seventy thousand of them.
 *
 * The same number bounds something else. The whole of a file is still pulled into memory before its tag has been
 * checked, so this is the most a single open can be made to allocate and read. It is no longer what a stranger gets
 * to spend, though: OpenVault reads the header alone until the commitment says the password was the right one, so a
 * file that is not this build's, or not this password's, costs kHeaderSize and the derivation its header asked for. */

inline constexpr int64_t kMaxSize = 4LL * 1024 * 1024;                                /// Maximum vault file size
inline constexpr int64_t kMinSize = (kHeaderSize + kIVSize + kCountSize + kTagSize);  /// Mininum vault file size

/* What is left of kMaxSize once the framing is paid for is the largest image that is ever encrypted, and it is
 * encrypted whole rather than in chunks the way decryption reads it back */

static_assert(kMaxSize - static_cast<int64_t>(kHeaderSize + kIVSize + kTagSize) <=
                  static_cast<int64_t>(std::numeric_limits<int>::max()),
              "The largest image kMaxSize leaves room for goes through a single EVP_EncryptUpdate call, which takes "
              "its length as an int, so a ceiling past that reaches it as a negative length rather than an error");

inline constexpr int kMaxSiteLen = 256;   /// Maximum length of site name
inline constexpr int kMaxAccLen = 256;    /// Maximum length of account
inline constexpr int kMaxPwLen = 32;      /// Maximum length of entry password
inline constexpr int kMinPwLen = 8;       /// Minimum length of entry password
inline constexpr int kDefaultPwLen = 16;  /// Default length of entry password

inline constexpr size_t kMinEntrySize = (sizeof(uint32_t) + 1) * 3;  // Minimum serialized entry size

enum class VaultAction : std::uint8_t {
  kCreate,
  kOpen,
};

/**
 * @enum	Result
 * @brief	Generic success/failure outcome of an operation
 */
enum class Result : std::uint8_t {
  kSuccess,
  kFailure,
};
