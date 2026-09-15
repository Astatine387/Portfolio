/**
 * @file	entry.cpp
 * @brief	Implementation of Entry struct
 * @author	Astatine387
 */

#include "core/entry.h"

#include <cstring>

#include "utils/byte_order.h"

namespace {

/**
 * @brief   Report whether the source buffer still holds a given number of bytes
 * @param   cur     Current read position, never past @p srclen
 * @param   srclen  Bytes available in the source buffer
 * @param   need    Bytes the next read wants
 * @return  true when the read fits
 *
 * A subtraction rather than cur + need > srclen. The addition was not wrong: @p need carries a length field taken
 * from the buffer being parsed and so can be as large as UINT32_MAX, but each of the three reads that supply one
 * also compares it against its field ceiling in the same condition, and a dlen past 256 is refused by that clause
 * whatever the addition did. What the subtraction changes is where that safety lives. It is a property of this
 * check rather than of the clause standing beside it, so raising a ceiling, or dropping one during a refactor,
 * cannot quietly put a wrapped sum back in front of a read. SecureBuffer::Subspan and Entry::PwSpan already bound
 * themselves this way, and this is the one place in the parser that did not.
 */
constexpr bool HasBytes(size_t cur, size_t srclen, size_t need) {
  return cur <= srclen && need <= srclen - cur;
}

}  // namespace

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

  if (pw_src.size() < pw_len) {
    return 0;
  }

  size_t cur = 0;
  uint32_t dlen;

  /* Write site */

  dlen = static_cast<uint32_t>(site.size());

  StoreLE32(dst.data() + cur, dlen);
  cur += sizeof(uint32_t);

  memcpy(dst.data() + cur, site.data(), dlen);
  cur += dlen;

  /* Write account */

  dlen = static_cast<uint32_t>(acc.size());

  StoreLE32(dst.data() + cur, dlen);
  cur += sizeof(uint32_t);

  memcpy(dst.data() + cur, acc.data(), dlen);
  cur += dlen;

  /* Write password from its source buffer */

  StoreLE32(dst.data() + cur, pw_len);
  cur += sizeof(uint32_t);

  if (pw_len > 0) {
    memcpy(dst.data() + cur, pw_src.data(), pw_len);
  }
  cur += pw_len;

  return cur;
}

size_t Entry::Deserialize(const uint8_t* src, size_t srclen, size_t base_off) {
  size_t cur = 0;
  uint32_t dlen;

  /* Read site */

  if (!HasBytes(cur, srclen, sizeof(uint32_t))) {
    return 0;
  }

  dlen = LoadLE32(src + cur);
  cur += sizeof(uint32_t);

  if (dlen > kMaxSiteLen || !HasBytes(cur, srclen, dlen)) {
    return 0;
  }

  site.assign(reinterpret_cast<const char*>(src + cur), dlen);
  cur += dlen;

  /* Read account */

  if (!HasBytes(cur, srclen, sizeof(uint32_t))) {
    return 0;
  }

  dlen = LoadLE32(src + cur);
  cur += sizeof(uint32_t);

  if (dlen > kMaxAccLen || !HasBytes(cur, srclen, dlen)) {
    return 0;
  }

  acc.assign(reinterpret_cast<const char*>(src + cur), dlen);
  cur += dlen;

  /* Read password length and record the view; the bytes stay in the image */

  if (!HasBytes(cur, srclen, sizeof(uint32_t))) {
    return 0;
  }

  dlen = LoadLE32(src + cur);
  cur += sizeof(uint32_t);

  if (dlen > kMaxEntryPwLen || !HasBytes(cur, srclen, dlen)) {
    return 0;
  }

  pw_len = dlen;
  pw_off = base_off + cur;
  cur += dlen;

  return cur;
}
