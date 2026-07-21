/**
 * @file	entry.h
 * @brief	Password entry
 * @author	Astatine387
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>

#include "common/constants.h"

/**
 * @struct     Entry
 * @brief      Password entry
 */
struct Entry {
  std::string site;
  std::string acc;
  mutable size_t pw_off = 0;  // Offset of the password bytes
  uint32_t pw_len = 0;        // Password length in bytes

  /**
   * @brief   Calculate serialized size in bytes
   * @return  Serialized size in bytes
   */
  [[nodiscard]] size_t Size() const;

  /**
   * @brief   Return offset of the password bytes in serialized form
   * @return  Byte offset of the password relative to the entry start
   */
  [[nodiscard]] size_t PwOffset() const;

  /**
   * @brief   Map password view onto an image span
   * @param   img     Span of the vault image
   * @return  Span of the password bytes, or std::nullopt when it falls outside the image
   */
  [[nodiscard]] std::optional<std::span<const uint8_t>> PwSpan(std::span<const uint8_t> img) const;

  /**
   * @brief   Serialize entry to buffer
   * @param   dst     Destination span, must have at least Size() bytes
   * @param   pw_src  Source of the password bytes, empty when the password is empty
   * @return  Number of bytes written, 0 when the destination is too small
   */
  size_t Serialize(std::span<uint8_t> dst, std::span<const uint8_t> pw_src) const;

  /**
   * @brief   Deserialize an entry, recording the password as a view into the image
   * @param   src         Source buffer
   * @param   srclen      Remaining bytes available in the source buffer
   * @param   base_off    Absolute offset of src
   * @return  Number of bytes read on success, 0 on failure
   */
  size_t Deserialize(const uint8_t* src, size_t srclen, size_t base_off);
};

/**
 * @struct  EntryCmp
 * @brief   Comparator for Entry set ordering
 */
struct EntryCmp {
  bool operator()(const Entry& a, const Entry& b) const {
    if (a.site != b.site) {
      return a.site < b.site;
    }

    return a.acc < b.acc;
  }
};
