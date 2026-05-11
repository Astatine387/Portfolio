/**
 * @file	Entry.h
 * @brief	Password entry
 * @author	Astatine387
 */

#pragma once

#include "Utils/Password.h"

#include <cstddef>
#include <cstdint>
#include <string>

#include "Common/constants.h"

/**
 * @struct     Entry
 * @brief      Password entry
 */
struct Entry {
  std::string site_;
  std::string acc_;
  Password pw_;

  /**
   * @brief   Calculate serialized size in bytes
   * @return  Serialized size in bytes
   */
  size_t Size() const;

  /**
   * @brief   Serialize entry to buffer
   * @param   dst     Destination buffer (must have enough space)
   * @return  Number of bytes written
   */
  size_t Ser(uint8_t* dst) const;

  /**
   * @brief   Deserialize entry from buffer
   * @param   src         Source buffer
   * @param   srcLen      Source buffer size
   * @return  Number of bytes read on success, 0 on failure
   */
  size_t Deser(const uint8_t* src, size_t srclen);
};

/**
 * @struct  EntryCmp
 * @brief   Comparator for Entry set ordering
 */
struct EntryCmp {
  bool operator()(const Entry& a, const Entry& b) const {
    if (a.site_ != b.site_) {
      return a.site_ < b.site_;
    }

    return a.acc_ < b.acc_;
  }
};