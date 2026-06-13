/**
 * @file	entry.cpp
 * @brief	Implementation of Entry struct
 * @author	Astatine387
 */

#include "core/entry.h"

#include <cstring>

size_t Entry::Size() const {
  return sizeof(uint32_t) + site.size() + sizeof(uint32_t) + acc.size() + sizeof(uint32_t) + pw.GetSize();
}

size_t Entry::Ser(uint8_t* dst) const {
  size_t cur = 0;
  uint32_t dlen;

  /* Write site */

  dlen = static_cast<uint32_t>(site.size());

  memcpy(dst + cur, &dlen, sizeof(uint32_t));
  cur += sizeof(uint32_t);

  memcpy(dst + cur, site.data(), dlen);
  cur += dlen;

  /* Write account */

  dlen = static_cast<uint32_t>(acc.size());

  memcpy(dst + cur, &dlen, sizeof(uint32_t));
  cur += sizeof(uint32_t);

  memcpy(dst + cur, acc.data(), dlen);
  cur += dlen;

  /* Write password */

  dlen = static_cast<uint32_t>(pw.GetSize());

  memcpy(dst + cur, &dlen, sizeof(uint32_t));
  cur += sizeof(uint32_t);

  if (dlen > 0) {
    memcpy(dst + cur, pw.GetData(), dlen);
  }
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

  site.assign(reinterpret_cast<const char*>(src + cur), dlen);
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

  acc.assign(reinterpret_cast<const char*>(src + cur), dlen);
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

  if (pw.SetData(reinterpret_cast<const char*>(src + cur), dlen) == Result::kFailure) {
    return 0;  // LCOV_EXCL_LINE
  }

  cur += dlen;

  return cur;
}