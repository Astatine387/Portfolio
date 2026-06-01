/**
 * @file	password.cpp
 * @brief	Implementation of Password class
 * @author	Astatine387
 */

#include "Utils/password.h"

#include <cstring>

#include "Utils/platform.h"

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

void Password::SetData(const Password& pw) {
  SetData(pw.GetData(), pw.GetSize());
}

void Password::SetData(const char* str, size_t len) {
  Clean();

  if (str) {
    size_ = len;
    data_ = new char[size_ + 1];

    locked_ = (Lock(data_, size_ + 1) == 0);
    memcpy(data_, str, size_);

    data_[size_] = '\0';
  }
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