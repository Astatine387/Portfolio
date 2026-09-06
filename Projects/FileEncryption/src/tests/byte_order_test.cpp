/**
 * @file    byte_order_test.cpp
 * @brief   Unit tests for the explicit byte order helpers
 * @author  Astatine387
 */

#include "utils/byte_order.h"

#include <gtest/gtest.h>

#include <array>
#include <cstdint>

/* ==================================================
 * Byte Order Tests
 * ================================================== */

/**
 * @brief   Round-trip a 32-bit value through the little-endian helpers at compile time
 * @param   val   Value to round-trip
 * @return  Value decoded back out of the buffer
 */
constexpr uint32_t RoundTripLE32(uint32_t val) {
  std::array<uint8_t, 4> buff{};

  StoreLE32(buff.data(), val);

  return LoadLE32(buff.data());
}

/* Evaluated by the compiler, so these cover something the runtime cases below cannot: that the helpers
 * stay usable in a constant expression. Losing constexpr would fail the build here rather than quietly
 * moving header field encoding to run time. */

static_assert(RoundTripLE32(0) == 0);
static_assert(RoundTripLE32(0xDEADBEEFU) == 0xDEADBEEFU);
static_assert(RoundTripLE32(UINT32_MAX) == UINT32_MAX);

/**
 * @brief   Verify StoreLE32 writes the least significant byte first
 */
TEST(ByteOrderTest, StoreLE32WritesLittleEndian) {
  std::array<uint8_t, 4> buff{};

  StoreLE32(buff.data(), 0x12345678U);

  EXPECT_EQ(buff, (std::array<uint8_t, 4>{ 0x78, 0x56, 0x34, 0x12 }));
}

/**
 * @brief   Verify LoadLE32 reads the least significant byte first
 */
TEST(ByteOrderTest, LoadLE32ReadsLittleEndian) {
  const std::array<uint8_t, 4> buff{ 0x78, 0x56, 0x34, 0x12 };

  EXPECT_EQ(LoadLE32(buff.data()), 0x12345678U);

  const std::array<uint8_t, 4> high{ 0xEF, 0xBE, 0xAD, 0xDE };

  EXPECT_EQ(LoadLE32(high.data()), 0xDEADBEEFU);
}

/**
 * @brief   Verify StoreBE64 writes the most significant byte first
 */
TEST(ByteOrderTest, StoreBE64WritesBigEndian) {
  std::array<uint8_t, 8> buff{};

  StoreBE64(buff.data(), 0x0123456789ABCDEFULL);

  EXPECT_EQ(buff, (std::array<uint8_t, 8>{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF }));
}

/**
 * @brief   Verify the 32-bit helpers round-trip every boundary value
 */
TEST(ByteOrderTest, RoundTrips32BitBoundaries) {
  const std::array<uint32_t, 7> cases{ 0U, 1U, 0xFFU, 0x100U, 0x80000000U, 0xFFFFFF00U, UINT32_MAX };

  for (uint32_t value : cases) {
    SCOPED_TRACE(testing::Message() << "value=" << value);

    std::array<uint8_t, 4> buff{};

    StoreLE32(buff.data(), value);

    EXPECT_EQ(LoadLE32(buff.data()), value);
  }
}

/**
 * @brief   Verify StoreBE64 encodes boundary values the way the nonce counter needs
 */
TEST(ByteOrderTest, StoreBE64EncodesBoundaries) {
  std::array<uint8_t, 8> buff{};

  StoreBE64(buff.data(), 0);
  EXPECT_EQ(buff, (std::array<uint8_t, 8>{ 0, 0, 0, 0, 0, 0, 0, 0 }));

  StoreBE64(buff.data(), 1);
  EXPECT_EQ(buff, (std::array<uint8_t, 8>{ 0, 0, 0, 0, 0, 0, 0, 1 }));

  StoreBE64(buff.data(), UINT64_MAX);
  EXPECT_EQ(buff, (std::array<uint8_t, 8>{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }));
}

/**
 * @brief   Verify the store helpers write exactly their field width and nothing beyond it
 */
TEST(ByteOrderTest, StoresStayInsideTheirField) {
  constexpr uint8_t kGuard = 0xCC;

  /* One guard byte on each side of the field, so the size follows the field width */

  std::array<uint8_t, sizeof(uint32_t) + 2> small{};
  std::array<uint8_t, sizeof(uint64_t) + 2> large{};

  small.fill(kGuard);
  large.fill(kGuard);

  StoreLE32(small.data() + 1, UINT32_MAX);
  StoreBE64(large.data() + 1, UINT64_MAX);

  EXPECT_EQ(small.front(), kGuard);
  EXPECT_EQ(small.back(), kGuard);
  EXPECT_EQ(large.front(), kGuard);
  EXPECT_EQ(large.back(), kGuard);
}
