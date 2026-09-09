/**
 * @file	byte_order.h
 * @brief	Explicit byte order helpers for on-disk integer fields
 * @author	Astatine387
 *
 * Every integer field of a vault file is little-endian, so the format stays the same on a host of either
 * order rather than following whatever the compiler happens to emit.
 */

#pragma once

#include <cstdint>

/**
 * @brief   Store a 32-bit value in little-endian order
 * @param   dst   Destination buffer, at least 4 bytes
 * @param   val     Value to store
 */
constexpr void StoreLE32(uint8_t* dst, uint32_t val) {
  dst[0] = static_cast<uint8_t>(val & 0xFFU);
  dst[1] = static_cast<uint8_t>((val >> 8) & 0xFFU);
  dst[2] = static_cast<uint8_t>((val >> 16) & 0xFFU);
  dst[3] = static_cast<uint8_t>((val >> 24) & 0xFFU);
}

/**
 * @brief   Load a 32-bit value stored in little-endian order
 * @param   src   Source buffer, at least 4 bytes
 * @return  Decoded value
 */
[[nodiscard]] constexpr uint32_t LoadLE32(const uint8_t* src) {
  return static_cast<uint32_t>(src[0]) | (static_cast<uint32_t>(src[1]) << 8) | (static_cast<uint32_t>(src[2]) << 16) |
         (static_cast<uint32_t>(src[3]) << 24);
}
