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
 * plausibly have written rather than at what Argon2id will accept. */

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

/* The locking budget every buffer holding plaintext is drawn from, and the arithmetic that says what one allocation
 * spends against it. sodium_malloc does not lock the bytes it was asked for: it places a canary ahead of them and
 * locks the whole pages that the two together cover, so an allocation one byte past a page boundary pins a further
 * page. The ceilings below are set against those rounded figures rather than against the sizes asked for.
 *
 * A 4 KiB page is an assumption of this arithmetic rather than something it reads off the machine. It holds on
 * x86-64, which is what this is built and measured on; where the page is larger, each allocation rounds up further
 * than LockedBytes accounts for and the budget below is no longer the conservative figure it is meant to be. */

inline constexpr size_t kPageSize = 4096;                  /// Page size the locking arithmetic assumes
inline constexpr size_t kCanarySize = 16;                  /// Canary libsodium places ahead of a sodium_malloc region
inline constexpr size_t kLockBudget = 8ULL * 1024 * 1024;  /// Locked memory one process is assumed to be granted
inline constexpr size_t kLockReserve = 32 * kPageSize;     /// Budget held back for what is locked beside the two images

/**
 * @brief   Report what an allocation of a given size spends against the locking budget
 * @param   size  Bytes asked of sodium_malloc
 * @return  Bytes sodium_malloc locks to satisfy the request
 */
constexpr size_t LockedBytes(size_t size) {
  return ((size + kCanarySize + kPageSize - 1) / kPageSize) * kPageSize;
}

/* A vault is never streamed. The whole of it is decrypted into sodium_malloc memory and held there for as long as it
 * stays open, beside an ordinary heap copy of the ciphertext of the same size, so this ceiling is in the end a claim
 * about how much memory one process can lock. Nothing enforces it while running: sodium_malloc does not report a
 * refused mlock, it hands back a perfectly good pointer and leaves the pages swappable, so a vault over the limit
 * does not fail to open. It opens with its plaintext no longer pinned and says nothing about it. There is no error to
 * catch, which is why this is a constant chosen to sit under the limit rather than a check written against it.
 *
 * What has to fit is two images, not one. CreateEntry, UpdateEntry and DeleteEntry each build the whole of the next
 * image into a fresh SecureBuffer while the installed one is still held, and CommitImage swaps them only once it has
 * verified the candidate, so every edit is a moment with both locked at once. The candidate is the larger of the
 * two: it is allocated before CommitImage's ceiling has had anything to say about it, so the insert that will be
 * refused is one that stands kMaxEntrySize above the image already installed. Sizing this constant against a single
 * image is what left the second one swappable, and a session image holds every entry password in the vault.
 *
 * The budget is the 8 MiB a systemd default grants, soft and hard alike, which is why raising the soft limit to the
 * hard one at startup gains nothing on such a machine. kLockReserve is what is held back from it for the session
 * key, the second key a password change derives beside it, the Password buffers the dialogs hold and libsodium's own
 * allocations. The rest is what the pair of images has to fit inside, and the static_assert beside kMaxEntrySize is
 * what holds them to it: this figure is chosen to satisfy that assert, not argued for here.
 *
 * Little is given up for it. The largest entry the parser will accept is kMaxEntrySize, 256 of site and 256 of
 * account and 256 of password beside the three 4-byte length fields, and 5,251 of those fit once the header, IV,
 * entry count and tag are paid for. Entries of the length a person actually types run nearer 60 bytes, which is some
 * sixty-eight thousand of them.
 *
 * The same number bounds something else. The whole of a file is still pulled into memory before its tag has been
 * checked, so this is the most a single open can be made to allocate and read. It is not what a stranger gets to
 * spend, though: OpenVault reads the header alone until the commitment says the password was the right one, so a
 * file that is not this build's, or not this password's, costs kHeaderSize and the derivation its header asked for. */

inline constexpr int64_t kMaxSize = 4000LL * 1024;                                    /// Maximum vault file size
inline constexpr int64_t kMinSize = (kHeaderSize + kIVSize + kCountSize + kTagSize);  /// Mininum vault file size
inline constexpr size_t kFrameSize = kHeaderSize + kIVSize + kTagSize;  /// Vault file bytes outside the image

/* What is left of kMaxSize once the framing is paid for is the largest image that is ever encrypted, and it is
 * encrypted whole rather than in chunks the way decryption reads it back. CommitImage refuses an image above it, so a
 * session never holds one that SaveVaultWith would have to turn away at the point of writing it.
 *
 * max is written parenthesized because a translation unit that reached windows.h before this header has a
 * function-like max macro in scope, and the bare call would be taken for an invocation of it with no arguments. */

inline constexpr int64_t kMaxImageSize = kMaxSize - static_cast<int64_t>(kFrameSize);  /// Largest image that fits

static_assert(kMaxImageSize <= static_cast<int64_t>((std::numeric_limits<int>::max)()),
              "The largest image kMaxSize leaves room for goes through a single EVP_EncryptUpdate call, which takes "
              "its length as an int, so a ceiling past that reaches it as a negative length rather than an error");

inline constexpr int kMaxSiteLen = 256;     /// Maximum length of site name
inline constexpr int kMaxAccLen = 256;      /// Maximum length of account
inline constexpr int kMaxEntryPwLen = 256;  /// Maximum stored length of entry password

/* An entry password is read back out of the image into a Password, which holds kMaxMasterPwLen bytes and refuses
 * anything longer. A ceiling above that would let the parser accept an entry whose password GetEntryPW could never
 * hand back, so the two are free to differ only in the one direction. */

static_assert(kMaxEntryPwLen <= kMaxMasterPwLen,
              "An entry password the parser accepts has to fit the Password buffer it is later copied into");

/* The generator produces a password of a length the user picks on a slider. These bound that slider and nothing
 * else: what the format stores is kMaxEntryPwLen, and a typed password is not generated at all. */

inline constexpr int kMaxGenPwLen = 32;      /// Maximum value of the generator slider
inline constexpr int kMinGenPwLen = 8;       /// Minimum value of the generator slider
inline constexpr int kDefaultGenPwLen = 16;  /// Default value of the generator slider

static_assert(kMaxGenPwLen <= kMaxEntryPwLen, "The generator can produce a password the vault cannot store");

/* The + 1 on each field is an assumption, not padding: every one of the three fields carries at least one byte, so
 * the smallest entry the format holds is three length prefixes and three single bytes. ValidateEntryFields is what
 * makes that true, refusing an empty site, account or password on the way in, and OpenVault is what spends it,
 * sizing its entry-count check on this figure before a single entry is parsed. Neither half is any use alone. Drop
 * a field's check and entries of 14 bytes reach the disk while the check still reads 15 apiece, so it refuses every
 * vault holding one; raise the figure without raising the ceilings and it refuses vaults that are perfectly well
 * formed. Either way the file was already written by the time anything notices. */

inline constexpr size_t kMinEntrySize = (sizeof(uint32_t) + 1) * 3;  /// Minimum serialized entry size

/* The other end of the same figure, and what an edit costs over the image it is editing. It is stated here rather
 * than left to the three ceilings because the locking budget is sized on it: the candidate image an insert builds is
 * exactly this much larger than the one already installed, and the assert below is where that shows up. */

inline constexpr size_t kMaxEntrySize =
    (sizeof(uint32_t) * 3) + kMaxSiteLen + kMaxAccLen + kMaxEntryPwLen;  /// Maximum serialized entry size

/* Where kMaxSize is actually decided. An edit holds the installed image and a candidate one entry larger at the same
 * time, and both are sodium_malloc regions, so the two rounded up and the reserve beside them are what the budget
 * has to cover. Stated as an assert rather than as the arithmetic in the comment above kMaxSize, because a ceiling
 * raised past the budget costs nothing a build or a test run would report: the locking simply stops happening. */

static_assert(LockedBytes(static_cast<size_t>(kMaxImageSize)) +
                      LockedBytes(static_cast<size_t>(kMaxImageSize) + kMaxEntrySize) + kLockReserve <=
                  kLockBudget,
              "The installed image and the candidate one entry above it no longer fit the locking budget together, "
              "which leaves the candidate swappable with every entry password in it");

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
