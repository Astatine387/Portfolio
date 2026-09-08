/**
 * @file	secure_key.cpp
 * @brief	Implementation of SecureKey and key derivation
 * @author	Astatine387
 */

#include "core/secure_key.h"

#include <argon2.h>
#include <sodium.h>

#include <algorithm>
#include <mutex>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/resource.h>
#endif

#if defined(__linux__) && defined(NDEBUG)
#include <sys/prctl.h>
#endif

namespace {

std::once_flag g_init_flag;

void DoInit() {
  if (sodium_init() < 0) {
    return;  // LCOV_EXCL_LINE  libsodium unavailable
  }

  /* sodium_malloc locks its pages so that a key cannot reach the swap file, but the lock is capped by the limits below
   * and fails quietly once the cap is reached. Raising them is best effort: a limit that will not move is not a reason
   * to refuse to run. */

#ifdef _WIN32
  /* Raise the working-set minimum so locked pages are permitted */

  SIZE_T min_ws = 0;
  SIZE_T max_ws = 0;
  HANDLE proc = GetCurrentProcess();

  if (GetProcessWorkingSetSize(proc, &min_ws, &max_ws)) {
    constexpr SIZE_T kBump = 4ULL * 1024 * 1024;
    SetProcessWorkingSetSize(proc, min_ws + kBump, max_ws + kBump);
  }

  /* Keep an unhandled exception from reaching the default Windows Error Reporting path, which is where a dump of this
   * process, Argon2id working buffer and all, would be written. SEM_FAILCRITICALERRORS comes along because the same
   * handler serves both dialogs and neither is useful in a program with no one watching it.
   *
   * Best effort in the same sense as the lock above, and worth being plain about: WER LocalDumps configured by an
   * administrator collects through a route this flag does not sit on, so the dump is still taken there. Nothing an
   * unprivileged process can call turns that off. */

  SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
#else
  /* Raise the RLIMIT_MEMLOCK soft limit to the hard limit */

  rlimit rl = {};

  if (getrlimit(RLIMIT_MEMLOCK, &rl) == 0) {
    rl.rlim_cur = rl.rlim_max;
    setrlimit(RLIMIT_MEMLOCK, &rl);
  }

  /* Refuse core dumps, in every build. sodium_malloc keeps the password and the derived key out of one already, since
   * sodium_mlock asks for MADV_DONTDUMP, but Argon2id's working buffer comes from libargon2's own malloc and lands in
   * the dump whole. That buffer is not a discardable intermediate: each lane's first two blocks come from H0, every
   * later block follows from those two, and the tag is the XOR of each lane's last block, so whoever reads the buffer
   * out of a dump recomputes the key without ever seeing the password. Locking 32 bytes while one crash spills the
   * 512 MiB that regenerate them is not a trade worth keeping, and no crash of this program is worth diagnosing at
   * that price. The hard limit goes down with the soft one so that nothing later in the process can put it back.
   *
   * The result is dropped rather than acted on. A limit that will not move is not a reason to refuse to run, the same
   * as with RLIMIT_MEMLOCK above, and DoInit runs before there is anywhere to report it to. The dumpable flag below
   * is a separate mechanism and is set whether this call succeeded or not. */

  rlimit no_core = {};

  static_cast<void>(setrlimit(RLIMIT_CORE, &no_core));

#if defined(__linux__) && defined(NDEBUG)
  /* A second, independent layer. RLIMIT_CORE bounds the core file the kernel is willing to write, while the dumpable
   * flag decides whether a dump is produced for this process at all, so it holds whatever core_pattern happens to
   * name. It also closes the other way the Argon2id buffer walks out: a process that is not dumpable cannot be
   * attached with PTRACE_ATTACH by the same uid, and its /proc entry becomes root's, so the buffer cannot be read out
   * of the live process either.
   *
   * That last property is exactly why this is held to NDEBUG. With the flag cleared, gdb and CLion cannot attach and
   * the sanitizer runtimes cannot read the process they are instrumenting. Sanitizer and coverage builds here require
   * CMAKE_BUILD_TYPE=Debug, so NDEBUG already separates the builds that have to stay inspectable from the ones that
   * ship, and no second switch has to be kept in sync with it.
   *
   * Dropped for the same reason as the limit above: best effort, and a kernel that refuses is not a reason to refuse
   * to run. */

  static_cast<void>(prctl(PR_SET_DUMPABLE, 0, 0, 0, 0));
#endif
#endif
}

}  // namespace

void InitCrypto() {
  std::call_once(g_init_flag, DoInit);
}

SecureKey::~SecureKey() {
  if (data_ != nullptr) {
    sodium_free(data_);  // sodium_free zeroes the region before releasing it
    data_ = nullptr;
  }
}

SecureKey::SecureKey(uint8_t* data, std::span<const uint8_t, kSaltSize> salt, const KdfParams& params)
    : data_(data), params_(params) {
  std::ranges::copy(salt, salt_.begin());
}

SecureKey::SecureKey(SecureKey&& other) noexcept : data_(other.data_), salt_(other.salt_), params_(other.params_) {
  other.data_ = nullptr;
}

SecureKey& SecureKey::operator=(SecureKey&& other) noexcept {
  if (this != &other) {
    if (data_ != nullptr) {
      sodium_free(data_);
    }

    data_ = other.data_;
    salt_ = other.salt_;
    params_ = other.params_;

    other.data_ = nullptr;
  }

  return *this;
}

std::span<const uint8_t, kKeySize> SecureKey::Bytes() const {
  return std::span<const uint8_t, kKeySize>(data_, kKeySize);
}

std::span<const uint8_t, kCommitSize> SecureKey::Commitment() const {
  return std::span<const uint8_t, kCommitSize>(data_ + kKeySize, kCommitSize);
}

std::span<const uint8_t, kSaltSize> SecureKey::Salt() const {
  return salt_;
}

const KdfParams& SecureKey::Params() const {
  return params_;
}

bool SecureKey::CommitmentMatches(std::span<const uint8_t, kCommitSize> expected) const {
  /* sodium_memcmp rather than memcmp, for the same reason ConstantTimeEquals uses it: memcmp stops at the first
   * differing byte, and how long it takes to do so tells an observer how much of a guessed password was right. The
   * commitment is public, but the time taken to reject one is not, and this comparison runs once per password attempt,
   * which is exactly where a guess would be timed. */

  return sodium_memcmp(data_ + kKeySize, expected.data(), kCommitSize) == 0;
}

bool SecureKey::ConstantTimeEquals(const SecureKey& other) const {
  /* sodium_memcmp rather than memcmp: memcmp stops at the first differing byte, and how long it takes to do so tells an
   * observer how much of a guessed key was right */

  return sodium_memcmp(data_, other.data_, kKeySize) == 0;
}

std::optional<SecureKey> DeriveKey(std::span<const char> pw, std::span<const uint8_t, kSaltSize> salt,
                                   const KdfParams& params) {
  InitCrypto();

  /* Argon2id writes straight into locked, self-wiping memory, so the derived key never exists in a plain buffer that
   * would have to be wiped afterwards */

  auto* key = static_cast<uint8_t*>(sodium_malloc(kDerivedSize));

  if (key == nullptr) {
    return std::nullopt;  // LCOV_EXCL_LINE
  }

  /* The parameters come from the file header on the decryption path, which is why ValidateHeader has to have bounded
   * them before this call.
   *
   * One derivation of kDerivedSize bytes rather than two of kKeySize: Argon2id is the expensive step here, and a longer
   * output costs nothing next to running it twice. The output length is part of what Argon2id hashes, so the key half
   * is not what a kKeySize derivation would have produced. */

  if (argon2id_hash_raw(params.time_cost, params.mem_cost, params.parallelism, pw.data(), pw.size(), salt.data(),
                        salt.size(), key, kDerivedSize) != ARGON2_OK) {
    /* SecureKey only takes ownership on the success path below, so the allocation is still this call's */

    sodium_free(key);
    return std::nullopt;
  }

  return SecureKey(key, salt, params);
}
