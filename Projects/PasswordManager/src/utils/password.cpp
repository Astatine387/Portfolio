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

  static const std::array<uint8_t, kMaxMasterPwLen + 1> kZero{};

  const void* lhs = (data_ != nullptr) ? static_cast<const void*>(data_) : static_cast<const void*>(kZero.data());
  const void* rhs =
      (other.data_ != nullptr) ? static_cast<const void*>(other.data_) : static_cast<const void*>(kZero.data());

  uint8_t len_diff = (size_ != other.size_) ? 1 : 0;
  int content_diff = sodium_memcmp(lhs, rhs, kMaxMasterPwLen);

  return len_diff == 0 && content_diff == 0;
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

  Clean();

  if (str != nullptr) {
    InitCrypto();

    data_ = static_cast<char*>(sodium_malloc(kMaxMasterPwLen + 1));

    if (data_ == nullptr) {
      return Result::kFailure;  // LCOV_EXCL_LINE
    }

    sodium_memzero(data_, kMaxMasterPwLen + 1);

    size_ = len;
    memcpy(data_, str, size_);
  }

  return Result::kSuccess;
}

void Password::Clean() {
  if (data_ != nullptr) {
    sodium_free(data_);  // sodium_free zeroes the region before releasing it
    data_ = nullptr;
  }

  size_ = 0;
}