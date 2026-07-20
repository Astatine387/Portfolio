/**
 * @file	secure_buffer.cpp
 * @brief	Implementation of SecureBuffer class
 * @author	Astatine387
 */

#include "core/secure_buffer.h"

#include <sodium.h>

#include "core/secure_key.h"

SecureBuffer::SecureBuffer(size_t size) : size_(size) {
  if (size_ > 0) {
    InitCrypto();
    data_ = static_cast<uint8_t*>(sodium_malloc(size_));
  }
}

SecureBuffer::~SecureBuffer() {
  Reset();
}

SecureBuffer::SecureBuffer(SecureBuffer&& other) noexcept : data_(other.data_), size_(other.size_) {
  other.data_ = nullptr;
  other.size_ = 0;
}

SecureBuffer& SecureBuffer::operator=(SecureBuffer&& other) noexcept {
  if (this != &other) {
    Reset();

    data_ = other.data_;
    size_ = other.size_;

    other.data_ = nullptr;
    other.size_ = 0;
  }

  return *this;
}

bool SecureBuffer::Valid() const {
  return size_ == 0 || data_ != nullptr;
}

uint8_t* SecureBuffer::Data() {
  return data_;
}

const uint8_t* SecureBuffer::Data() const {
  return data_;
}

size_t SecureBuffer::Size() const {
  return size_;
}

void SecureBuffer::Reset() {
  if (data_ != nullptr) {
    sodium_free(data_);  // sodium_free zeroes the buffer before releasing it
    data_ = nullptr;
  }

  size_ = 0;
}