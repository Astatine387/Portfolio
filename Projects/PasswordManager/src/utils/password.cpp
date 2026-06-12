/**
 * @file	password.cpp
 * @brief	Implementation of Password class
 * @author	Astatine387
 */

#include "utils/password.h"

#include <cstring>

#include "utils/platform.h"

bool Password::Equal(const Password& other) const {
  volatile uint8_t diff = (size_ != other.size_) ? 1 : 0;

  for (size_t i = 0; i < kMaxPWLen; i++) {
    uint8_t a = (data_ != nullptr) ? static_cast<uint8_t>(data_[i]) : 0;
    uint8_t b = (other.data_ != nullptr) ? static_cast<uint8_t>(other.data_[i]) : 0;

    diff |= a ^ b;
  }

  return diff == 0;
}

bool Password::IsEmpty() const {
  return size_ == 0;
}

bool Password::IsLocked() const {
  return locked_;
}

const char* Password::GetData() const {
  return data_;
}

size_t Password::GetSize() const {
  return size_;
}

Result Password::SetData(const Password& pw) {
  return SetData(pw.GetData(), pw.GetSize());
}

Result Password::SetData(const char* str, size_t len) {
  if (len > kMaxPWLen) {
    return Result::kFailure;
  }

  Clean();

  if (str) {
    size_ = len;

    data_ = new char[kMaxPWLen + 1]{};

    locked_ = (Lock(data_, kMaxPWLen + 1) == Result::kSuccess);
    memcpy(data_, str, size_);
  }

  return Result::kSuccess;
}

void Password::Clean() {
  if (data_ != nullptr) {
    Wipe(data_, kMaxPWLen + 1);
    Unlock(data_, kMaxPWLen + 1);

    delete[] data_;
  }

  data_ = nullptr;
  size_ = 0;
  locked_ = false;
}