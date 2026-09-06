/**
 * @file	password.cpp
 * @brief	Implementation of Password class
 * @author	Astatine387
 */

#include "utils/password.h"

#include <sodium.h>

#include <cstring>

#include "core/secure_key.h"

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
  /* Self-assignment would wipe the source in Clean() before there is anything left to copy from */

  if (this == &pw) {
    return Result::kSuccess;
  }

  return SetData(pw.GetData(), pw.GetSize());
}

Result Password::SetData(const char* str, size_t len) {
  /* Wipe first: whatever is held now is gone either way, and a failed allocation below must not leave the
   * previous password behind */

  Clean();

  if (str != nullptr) {
    InitCrypto();

    /* sodium_malloc locks the pages against the swap file and wipes them on release. The extra byte is
     * the terminator, which lets the buffer be handed to a C interface without a copy. */

    data_ = static_cast<char*>(sodium_malloc(len + 1));

    if (data_ == nullptr) {
      return Result::kFailure;  // LCOV_EXCL_LINE  secure allocation failed
    }

    size_ = len;
    memcpy(data_, str, size_);

    data_[size_] = '\0';
  }

  return Result::kSuccess;
}

void Password::Clean() {
  if (data_ != nullptr) {
    sodium_free(data_);  // sodium_free zeroes the buffer before releasing it
    data_ = nullptr;
  }

  size_ = 0;
}
