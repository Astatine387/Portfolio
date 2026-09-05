/**
 * @file	byte_order.h
 * @brief	Explicit byte order helpers for on-disk integer fields
 * @author	Astatine387
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

/**
 * @brief   Store a 64-bit value in big-endian order
 * @param   dst   Destination buffer, at least 8 bytes
 * @param   val     Value to store
 */
constexpr void StoreBE64(uint8_t* dst, uint64_t val) {
  dst[0] = static_cast<uint8_t>((val >> 56) & 0xFFU);
  dst[1] = static_cast<uint8_t>((val >> 48) & 0xFFU);
  dst[2] = static_cast<uint8_t>((val >> 40) & 0xFFU);
  dst[3] = static_cast<uint8_t>((val >> 32) & 0xFFU);
  dst[4] = static_cast<uint8_t>((val >> 24) & 0xFFU);
  dst[5] = static_cast<uint8_t>((val >> 16) & 0xFFU);
  dst[6] = static_cast<uint8_t>((val >> 8) & 0xFFU);
  dst[7] = static_cast<uint8_t>(val & 0xFFU);
}
