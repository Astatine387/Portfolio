/**
 * @file	Entry.cpp
 * @brief	Implementation of Entry struct
 * @author	Astatine387
 */

#include "Core/Entry.h"

#include <cstring>

size_t Entry::Size() const {
  return sizeof(uint32_t) + site_.size() + sizeof(uint32_t) + acc_.size() + sizeof(uint32_t) +
         pw_.GetSize();
}

size_t Entry::Ser(uint8_t* dst) const {
  size_t cur = 0;
  uint32_t dlen;

  /* Write site */

  dlen = static_cast<uint32_t>(site_.size());

  memcpy(dst + cur, &dlen, sizeof(uint32_t));
  cur += sizeof(uint32_t);

  memcpy(dst + cur, site_.data(), dlen);
  cur += dlen;

  /* Write account */

  dlen = static_cast<uint32_t>(acc_.size());

  memcpy(dst + cur, &dlen, sizeof(uint32_t));
  cur += sizeof(uint32_t);

  memcpy(dst + cur, acc_.data(), dlen);
  cur += dlen;

  /* Write password */

  dlen = static_cast<uint32_t>(pw_.GetSize());

  memcpy(dst + cur, &dlen, sizeof(uint32_t));
  cur += sizeof(uint32_t);

  memcpy(dst + cur, pw_.GetData(), dlen);
  cur += dlen;

  return cur;
}

size_t Entry::Deser(const uint8_t* src, size_t srclen) {
  size_t cur = 0;
  uint32_t dlen;

  /* Read site */

  if (cur + sizeof(uint32_t) > srclen) {
    return 0;
  }

  memcpy(&dlen, src + cur, sizeof(uint32_t));
  cur += sizeof(uint32_t);

  if (cur + dlen > srclen || dlen > kMaxSiteLen) {
    return 0;
  }

  site_.assign(reinterpret_cast<const char*>(src + cur), dlen);
  cur += dlen;

  /* Read account */

  if (cur + sizeof(uint32_t) > srclen) {
    return 0;
  }

  memcpy(&dlen, src + cur, sizeof(uint32_t));
  cur += sizeof(uint32_t);

  if (cur + dlen > srclen || dlen > kMaxAccLen) {
    return 0;
  }

  acc_.assign(reinterpret_cast<const char*>(src + cur), dlen);
  cur += dlen;

  /* Read password */

  if (cur + sizeof(uint32_t) > srclen) {
    return 0;
  }

  memcpy(&dlen, src + cur, sizeof(uint32_t));
  cur += sizeof(uint32_t);

  if (cur + dlen > srclen || dlen > kMaxPWLen) {
    return 0;
  }

  if (pw_.SetData(reinterpret_cast<const char*>(src + cur), dlen)) {
    return 0;
  }

  cur += dlen;

  return cur;
}