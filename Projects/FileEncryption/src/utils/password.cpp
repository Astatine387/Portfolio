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
  if (str == nullptr) {
    Clean();
    return Result::kSuccess;
  }

  InitCrypto();

  /* sodium_malloc locks the pages against the swap file and wipes them on release. The extra byte is
   * the terminator, which lets the buffer be handed to a C interface without a copy.
   *
   * The new buffer is filled before the old one is released. @p str is allowed to point into data_ itself,
   * since GetData hands that pointer out, and releasing first would leave the copy below reading an
   * address this process no longer owns. */

  auto* fresh = static_cast<char*>(sodium_malloc(len + 1));

  if (fresh == nullptr) {
    // LCOV_EXCL_START  secure allocation failed
    Clean();  // Whatever was held is gone either way, which is what the caller is told on kFailure
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  memcpy(fresh, str, len);

  fresh[len] = '\0';

  Clean();

  data_ = fresh;
  size_ = len;

  return Result::kSuccess;
}

void Password::Clean() {
  if (data_ != nullptr) {
    sodium_free(data_);  // sodium_free zeroes the buffer before releasing it
    data_ = nullptr;
  }

  size_ = 0;
}
