/**
 * @file	password.cpp
 * @brief	Implementation of Password class
 * @author	Astatine387
 */

#include "Utils/password.h"

#include <cstring>

#include "Utils/library.h"

bool Password::Equal(const Password& other) const {
  volatile uint8_t diff = (size_ != other.size_) ? 1 : 0;
  size_t min_size = (size_ < other.size_) ? size_ : other.size_;

  for (size_t i = 0; i < kMaxPWLen; i++) {
    uint8_t a = (i >= min_size) ? 0 : static_cast<uint8_t>(data_[i]);
    uint8_t b = (i >= min_size) ? 0 : static_cast<uint8_t>(other.data_[i]);

    diff |= a ^ b;
  }

  return diff == 0;
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

int Password::SetData(const Password& pw) {
  return SetData(pw.GetData(), pw.GetSize());
}

int Password::SetData(const char* str, size_t len) {
  if (len > kMaxPWLen) {
    return 1;
  }

  Clean();

  if (str) {
    size_ = len;
    data_ = new char[size_ + 1];

    Lock(data_, size_ + 1);
    memcpy(data_, str, size_);

    data_[size_] = '\0';
  }

  return 0;
}

void Password::Clean() {
  if (data_ != nullptr) {
    Wipe(data_, size_ + 1);
    Unlock(data_, size_ + 1);

    delete[] data_;
  }

  data_ = nullptr;
  size_ = 0;
}