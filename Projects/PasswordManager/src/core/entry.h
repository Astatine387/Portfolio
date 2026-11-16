/**
 * @file    entry.h
 * @brief   Password entry
 * @author  Astatine387
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>

#include "common/constants.h"

/**
 * @brief   Password entry
 */
struct Entry {
  std::string site;
  std::string acc;
  size_t pw_off = 0;    // Offset of the password bytes
  uint32_t pw_len = 0;  // Password length in bytes

  /**
   * @brief   Calculate serialized size in bytes
   * @return  Serialized size in bytes
   */
  [[nodiscard]] size_t Size() const;

  /**
   * @brief   Return offset of the password bytes in serialized form
   * @return  Byte offset of the password from the entry start
   */
  [[nodiscard]] size_t PwOffset() const;

  /**
   * @brief   Map password view onto an image span
   * @param   img   Span of the vault image
   * @return  Span of the password bytes, or std::nullopt on failure
   */
  [[nodiscard]] std::optional<std::span<const uint8_t>> PwSpan(
      std::span<const uint8_t> img) const;

  /**
   * @brief   Serialize entry to buffer
   * @param   dst     Destination span
   * @param   pw_src  Source of the password bytes
   * @return  Number of bytes written, 0 on failure
   */
  [[nodiscard]] size_t Serialize(std::span<uint8_t> dst,
                                 std::span<const uint8_t> pw_src) const;

  /**
   * @brief   Deserialize buffer to entry
   * @param   src       Source buffer
   * @param   srclen    Remaining bytes available in the source buffer
   * @param   base_off  Absolute offset of src
   * @return  Number of bytes read on success, 0 on failure
   */
  size_t Deserialize(const uint8_t* src, size_t srclen, size_t base_off);
};

/**
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
