/**
 * @file	entry.cpp
 * @brief	Implementation of Entry struct
 * @author	Astatine387
 */

#include "core/entry.h"

#include <cstring>

size_t Entry::Size() const {
  return sizeof(uint32_t) + site.size() + sizeof(uint32_t) + acc.size() + sizeof(uint32_t) + pw_len;
}

size_t Entry::Serialize(uint8_t* dst, const uint8_t* pw_src) const {
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

  /* Write password from its source buffer */

  memcpy(dst + cur, &pw_len, sizeof(uint32_t));
  cur += sizeof(uint32_t);

  if (pw_len > 0 && pw_src != nullptr) {
    memcpy(dst + cur, pw_src, pw_len);
  }
  cur += pw_len;

  return cur;
}

size_t Entry::Deserialize(const uint8_t* src, size_t srclen, size_t base_off) {
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

  /* Read password length and record the view; the bytes stay in the image */

  if (cur + sizeof(uint32_t) > srclen) {
    return 0;
  }

  memcpy(&dlen, src + cur, sizeof(uint32_t));
  cur += sizeof(uint32_t);

  if (cur + dlen > srclen || dlen > kMaxPWLen) {
    return 0;
  }

  pw_len = dlen;
  pw_off = base_off + cur;
  cur += dlen;

  return cur;
}
