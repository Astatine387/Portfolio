/**
 * @file    secure_key.cpp
 * @brief   Implementation of SecureKey and key derivation
 * @author  Astatine387
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

std::once_flag g_init_flag;  // Whether DoInit() has run

/**
 * @brief   Initialize libsodium, best-effort raise the memory-lock limit, and
 * refuse core dumps
 */
void DoInit() {
  /* Initialize libsodium */

  if (sodium_init() < 0) {
    return;  // LCOV_EXCL_LINE
  }

#ifdef _WIN32
  /* Raise the working set minimum */

  SIZE_T min_ws = 0;
  SIZE_T max_ws = 0;
  HANDLE proc = GetCurrentProcess();

  if (GetProcessWorkingSetSize(proc, &min_ws, &max_ws)) {
    constexpr SIZE_T kBump = 4ULL * 1024 * 1024;
    SetProcessWorkingSetSize(proc, min_ws + kBump, max_ws + kBump);
  }

  /* Refuse core dump on crash  */

  SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
#else
  /* Raise the memory-lock soft limit to the hard limit */

  rlimit mem_limit = {};

  if (getrlimit(RLIMIT_MEMLOCK, &mem_limit) == 0) {
    mem_limit.rlim_cur = mem_limit.rlim_max;
    setrlimit(RLIMIT_MEMLOCK, &mem_limit);
  }

  /* Refuse core dumps */

  rlimit core_limit = {};

  static_cast<void>(setrlimit(RLIMIT_CORE, &core_limit));

#if defined(__linux__) && defined(NDEBUG)
  static_cast<void>(prctl(PR_SET_DUMPABLE, 0, 0, 0, 0));
#endif
#endif
}

}  // namespace

void InitCrypto() {
  /* Make DoInit() idempotent and safe to call multiple times */

  std::call_once(g_init_flag, DoInit);
}

SecureKey::~SecureKey() {
  if (data_ != nullptr) {
    sodium_free(data_);  // sodium_free zeroes the region before releasing it
    data_ = nullptr;
  }
}

SecureKey::SecureKey(uint8_t* data, std::span<const uint8_t, kSaltSize> salt,
                     const KdfParams& params)
    : data_(data), params_(params) {
  std::ranges::copy(salt, salt_.begin());
}

SecureKey::SecureKey(SecureKey&& other) noexcept
    : data_(other.data_), salt_(other.salt_), params_(other.params_) {
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

bool SecureKey::CommitmentMatches(
    std::span<const uint8_t, kCommitSize> other) const {
  /* sodium_memcmp rather than memcmp: memcmp stops at the first differing byte,
   * and how long it takes to do so tells an observer how much of a guessed key
   * was right */

  return sodium_memcmp(data_ + kKeySize, other.data(), kCommitSize) == 0;
}

bool SecureKey::ConstantTimeEquals(const SecureKey& other) const {
  /* sodium_memcmp rather than memcmp: memcmp stops at the first differing byte,
   * and how long it takes to do so tells an observer how much of a guessed key
   * was right */

  return sodium_memcmp(data_, other.data_, kKeySize) == 0;
}

std::optional<SecureKey> DeriveKey(std::span<const char> pw,
                                   std::span<const uint8_t, kSaltSize> salt,
                                   const KdfParams& params) {
  InitCrypto();

  /* Argon2id writes into locked, self-wiping memory */

  auto* key = static_cast<uint8_t*>(sodium_malloc(kDerivedSize));

  if (key == nullptr) {
    return std::nullopt;  // LCOV_EXCL_LINE
  }

  if (argon2id_hash_raw(params.time_cost, params.mem_cost, params.parallelism,
                        pw.data(), pw.size(), salt.data(), salt.size(), key,
                        kDerivedSize) != ARGON2_OK) {
    sodium_free(key);
    return std::nullopt;
  }

  return SecureKey(key, salt, params);
}
