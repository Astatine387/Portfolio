/**
 * @file	secure_buffer.cpp
 * @brief	Implementation of SecureBuffer class
 * @author	Astatine387
 */

#include "core/secure_buffer.h"

#include <sodium.h>

#include <algorithm>
#include <cstring>

#include "core/secure_key.h"

namespace {

constexpr size_t kRedzoneSize = 16;     // Trailing guard bytes appended after the logical region
constexpr uint8_t kRedzoneByte = 0xDB;  // Fill pattern for the redzone

}  // namespace

SecureBuffer::SecureBuffer(size_t size) : size_(size) {
  if (size_ > 0) {
    InitCrypto();

    data_ = static_cast<uint8_t*>(sodium_malloc(size_ + kRedzoneSize));

    if (data_ != nullptr) {
      memset(data_ + size_, kRedzoneByte, kRedzoneSize);
    }
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

std::span<uint8_t> SecureBuffer::Span() {
  return { data_, size_ };
}

std::span<const uint8_t> SecureBuffer::Span() const {
  return { data_, size_ };
}

std::optional<std::span<uint8_t>> SecureBuffer::Subspan(size_t off, size_t len) {
  if (off > size_ || len > size_ - off) {
    return std::nullopt;
  }

  return std::span<uint8_t>{ data_ + off, len };
}

std::optional<std::span<const uint8_t>> SecureBuffer::Subspan(size_t off, size_t len) const {
  if (off > size_ || len > size_ - off) {
    return std::nullopt;
  }

  return std::span<const uint8_t>{ data_ + off, len };
}

bool SecureBuffer::RedzoneIntact() const {
  if (data_ == nullptr) {
    return true;
  }

  std::span<const uint8_t> redzone{ data_ + size_, kRedzoneSize };

  return std::ranges::all_of(redzone, [](uint8_t byte) { return byte == kRedzoneByte; });
}

void SecureBuffer::Reset() {
  if (data_ != nullptr) {
    sodium_free(data_);  // sodium_free zeroes the buffer before releasing it
    data_ = nullptr;
  }

  size_ = 0;
}