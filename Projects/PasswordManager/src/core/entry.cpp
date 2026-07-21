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

size_t Entry::PwOffset() const {
  return Size() - pw_len;
}

std::optional<std::span<const uint8_t>> Entry::PwSpan(std::span<const uint8_t> img) const {
  if (pw_off > img.size() || pw_len > img.size() - pw_off) {
    return std::nullopt;
  }

  return img.subspan(pw_off, pw_len);
}

size_t Entry::Serialize(std::span<uint8_t> dst, std::span<const uint8_t> pw_src) const {
  if (dst.size() < Size()) {
    return 0;
  }

  size_t cur = 0;
  uint32_t dlen;

  /* Write site */

  dlen = static_cast<uint32_t>(site.size());

  memcpy(dst.data() + cur, &dlen, sizeof(uint32_t));
  cur += sizeof(uint32_t);

  memcpy(dst.data() + cur, site.data(), dlen);
  cur += dlen;

  /* Write account */

  dlen = static_cast<uint32_t>(acc.size());

  memcpy(dst.data() + cur, &dlen, sizeof(uint32_t));
  cur += sizeof(uint32_t);

  memcpy(dst.data() + cur, acc.data(), dlen);
  cur += dlen;

  /* Write password from its source buffer */

  memcpy(dst.data() + cur, &pw_len, sizeof(uint32_t));
  cur += sizeof(uint32_t);

  if (pw_len > 0 && pw_src.size() >= pw_len) {
    memcpy(dst.data() + cur, pw_src.data(), pw_len);
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
