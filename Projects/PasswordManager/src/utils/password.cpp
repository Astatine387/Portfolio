/**
 * @file	password.cpp
 * @brief	Implementation of Password class
 * @author	Astatine387
 */

#include "utils/password.h"

#include <sodium.h>

#include <array>
#include <cstdint>
#include <cstring>

#include "core/secure_key.h"

bool Password::Equal(const Password& other) const {
  /* Compare over the full buffer in constant time; also require equal length */

  static constexpr std::array<uint8_t, kMaxMasterPwLen + 1> kZero{};

  const void* l = (data_ != nullptr) ? static_cast<const void*>(data_) : static_cast<const void*>(kZero.data());
  const void* r =
      (other.data_ != nullptr) ? static_cast<const void*>(other.data_) : static_cast<const void*>(kZero.data());

  uint8_t len_diff = (size_ != other.size_) ? 1 : 0;
  int data_diff = sodium_memcmp(l, r, kMaxMasterPwLen);

  return len_diff == 0 && data_diff == 0;
}

bool Password::IsEmpty() const {
  return size_ == 0;
}

const char* Password::GetData() const {
  return data_;
}

size_t Password::GetSize() const {
  return size_;
}

Result Password::SetData(const Password& pw) {
  if (this == &pw) {
    return Result::kSuccess;
  }

  return SetData(pw.GetData(), pw.GetSize());
}

Result Password::SetData(const char* str, size_t len) {
  if (len > kMaxMasterPwLen) {
    return Result::kFailure;
  }

  if (str == nullptr) {
    Clean();
    return Result::kSuccess;
  }

  /* The new buffer is filled before the old one is released. @p str may point into data_ itself, since GetData hands
   * that pointer out, and releasing first would leave the copy below reading an address this process no longer owns.
   * Building the replacement first is also what leaves the current value untouched when the allocation is refused. */

  InitCrypto();

  auto* fresh = static_cast<char*>(sodium_malloc(kMaxMasterPwLen + 1));

  if (fresh == nullptr) {
    return Result::kFailure;  // LCOV_EXCL_LINE
  }

  sodium_memzero(fresh, kMaxMasterPwLen + 1);
  memcpy(fresh, str, len);

  Clean();

  data_ = fresh;
  size_ = len;

  return Result::kSuccess;
}

void Password::Clean() {
  if (data_ != nullptr) {
    sodium_free(data_);  // sodium_free zeroes the region before releasing it
    data_ = nullptr;
  }

  size_ = 0;
}
