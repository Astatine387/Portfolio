/**
 * @file	secure_key.cpp
 * @brief	Implementation of SecureKey and key derivation
 * @author	Astatine387
 */

#include "core/secure_key.h"

#include <argon2.h>
#include <sodium.h>

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
    return;  // LCOV_EXCL_LINE  libsodium unavailable; secure allocations fail loudly later
  }

#ifdef _WIN32
  /* Best-effort: raise the working-set minimum so locked pages are permitted */

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
   * Best effort in the same sense as the working set above, and worth being plain about: WER LocalDumps configured by
   * an administrator collects through a route this flag does not sit on, so the dump is still taken there. Nothing an
   * unprivileged process can call turns that off. */

  SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
#else
  /* Best-effort: raise the RLIMIT_MEMLOCK soft limit to the hard limit */

  rlimit rl{};

  if (getrlimit(RLIMIT_MEMLOCK, &rl) == 0) {
    rl.rlim_cur = rl.rlim_max;
    setrlimit(RLIMIT_MEMLOCK, &rl);
  }

  /* Refuse core dumps, in every build. sodium_malloc keeps the master password, the session key and the decrypted
   * vault image out of one already, since sodium_mlock asks for MADV_DONTDUMP, but Argon2id's working buffer comes
   * from libargon2's own malloc and lands in the dump whole. That buffer is not a discardable intermediate: each
   * lane's first two blocks come from H0, every later block follows from those two, and the tag is the XOR of each
   * lane's last block, so whoever reads the buffer out of a dump recomputes the session key without ever seeing the
   * master password. This process is a GUI that stays open for as long as the vault does, so the window in which a
   * crash could spill those 512 MiB is the whole session rather than one derivation. The hard limit goes down with
   * the soft one so that nothing later in the process can put it back.
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
   * That last property is why this is held to NDEBUG: with the flag cleared, gdb and CLion cannot attach to a running
   * PasswordManager. NDEBUG is the whole condition, so this is active in Release and in RelWithDebInfo, which is what
   * the sanitizer job builds, and inactive in Debug, which is what a local debugging session and the coverage job
   * build. It was measured on GCC 13 / Linux before being relied on: ASan and LeakSanitizer, including their
   * multi-threaded paths, behave the same with the flag cleared, and /proc/self/exe and /proc/self/maps stay readable
   * by the process itself, so Qt's applicationFilePath() and everything else reading its own /proc still works.
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

SecureKey::SecureKey(SecureKey&& other) noexcept : data_(other.data_) {
  other.data_ = nullptr;
}

SecureKey& SecureKey::operator=(SecureKey&& other) noexcept {
  if (this != &other) {
    if (data_ != nullptr) {
      sodium_free(data_);
    }

    data_ = other.data_;
    other.data_ = nullptr;
  }

  return *this;
}

std::span<const uint8_t, kKeySize> SecureKey::Bytes() const {
  return std::span<const uint8_t, kKeySize>(data_, kKeySize);
}

bool SecureKey::ConstantTimeEquals(const SecureKey& other) const {
  return sodium_memcmp(data_, other.data_, kKeySize) == 0;
}

std::optional<SecureKey> DeriveKey(std::span<const char> pw, std::span<const uint8_t, kSaltSize> salt,
                                   const KdfParams& params) {
  InitCrypto();

  auto* key = static_cast<uint8_t*>(sodium_malloc(kKeySize));

  if (key == nullptr) {
    return std::nullopt;  // LCOV_EXCL_LINE
  }

  if (argon2id_hash_raw(params.time_cost, params.mem_cost, params.parallelism, pw.data(), pw.size(), salt.data(),
                        salt.size(), key, kKeySize) != ARGON2_OK) {
    sodium_free(key);
    return std::nullopt;
  }

  return SecureKey(key);
}
