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

namespace {

std::once_flag g_init_flag;

void DoInit() {
  if (sodium_init() < 0) {
    return;  // LCOV_EXCL_LINE  libsodium unavailable
  }

#ifdef _WIN32
  /* Raise the working-set minimum so locked pages are permitted */

  SIZE_T min_ws = 0;
  SIZE_T max_ws = 0;
  HANDLE proc = GetCurrentProcess();

  if (GetProcessWorkingSetSize(proc, &min_ws, &max_ws)) {
    constexpr SIZE_T kBump = 4ULL * 1024 * 1024;
    SetProcessWorkingSetSize(proc, min_ws + kBump, max_ws + kBump);
  }
#else
  /* Raise the RLIMIT_MEMLOCK soft limit to the hard limit */

  rlimit rl = {};

  if (getrlimit(RLIMIT_MEMLOCK, &rl) == 0) {
    rl.rlim_cur = rl.rlim_max;
    setrlimit(RLIMIT_MEMLOCK, &rl);
  }
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
