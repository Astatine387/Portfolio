/**
 * @file	entry.h
 * @brief	Password entry
 * @author	Astatine387
 */

#pragma once

#include <cstddef>
#include <cstdint>
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
   * @brief   Serialize entry to buffer
   * @param   dst     Destination buffer (must have enough space)
   * @param   pw_src  Source of the password bytes, or nullptr when empty
   * @return  Number of bytes written
   */
  size_t Serialize(uint8_t* dst, const uint8_t* pw_src) const;

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
