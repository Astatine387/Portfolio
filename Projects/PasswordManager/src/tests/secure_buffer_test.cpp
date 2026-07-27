/**
 * @file    secure_buffer_test.cpp
 * @brief   Unit tests for SecureBuffer class
 * @author  Astatine387
 */

#include "core/secure_buffer.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <span>

/* ==================================================
 * Allocation Test
 * ================================================== */

/**
 * @brief   Verify a sized buffer allocates and reports its logical size
 */
TEST(SecureBufferTest, AllocatesLogicalSize) {
  SecureBuffer buff(64);

  EXPECT_TRUE(buff.Valid());
  EXPECT_EQ(buff.Size(), 64u);
  EXPECT_NE(buff.Data(), nullptr);
}

/**
 * @brief   Verify a default buffer is empty and valid
 */
TEST(SecureBufferTest, EmptyBufferIsValid) {
  SecureBuffer buff;

  EXPECT_TRUE(buff.Valid());
  EXPECT_EQ(buff.Size(), 0u);
  EXPECT_TRUE(buff.Span().empty());
}

/* ==================================================
 * Span Test
 * ================================================== */

/**
 * @brief   Verify Span covers exactly the logical region
 */
TEST(SecureBufferTest, SpanCoversLogicalRegion) {
  SecureBuffer buff(32);

  std::span<uint8_t> span = buff.Span();

  EXPECT_EQ(span.size(), 32u);
  EXPECT_EQ(span.data(), buff.Data());
}

/**
 * @brief   Verify the const Span overload covers the logical region
 */
TEST(SecureBufferTest, ConstSpanCoversLogicalRegion) {
  SecureBuffer buff(32);
  const SecureBuffer& cbuff = buff;

  std::span<const uint8_t> span = cbuff.Span();

  EXPECT_EQ(span.size(), 32u);
  EXPECT_EQ(span.data(), cbuff.Data());
}

/* ==================================================
 * Subspan Test
 * ================================================== */

/**
 * @brief   Verify Subspan returns an in-range subrange
 */
TEST(SecureBufferTest, SubspanInRange) {
  SecureBuffer buff(32);

  auto sub = buff.Subspan(8, 16);

  ASSERT_TRUE(sub.has_value());

  std::span<uint8_t> view = sub.value();  // NOLINT(bugprone-unchecked-optional-access)

  EXPECT_EQ(view.size(), 16u);
  EXPECT_EQ(view.data(), buff.Data() + 8);
}

/**
 * @brief   Verify a whole-region Subspan is accepted
 */
TEST(SecureBufferTest, SubspanWholeRegion) {
  SecureBuffer buff(32);

  auto sub = buff.Subspan(0, 32);

  ASSERT_TRUE(sub.has_value());
  EXPECT_EQ(sub.value().size(), 32u);  // NOLINT(bugprone-unchecked-optional-access)
}

/**
 * @brief   Verify Subspan rejects a range that runs past the end
 */
TEST(SecureBufferTest, SubspanPastEnd) {
  SecureBuffer buff(32);

  EXPECT_FALSE(buff.Subspan(16, 20).has_value());  // 16 + 20 > 32
  EXPECT_FALSE(buff.Subspan(33, 0).has_value());   // Offset past the end
}

/**
 * @brief   Verify Subspan rejects a length that overflows the offset
 */
TEST(SecureBufferTest, SubspanOverflow) {
  SecureBuffer buff(32);

  EXPECT_FALSE(buff.Subspan(8, SIZE_MAX).has_value());
}

/**
 * @brief   Verify the const Subspan overload is bounds-checked
 */
TEST(SecureBufferTest, ConstSubspanChecked) {
  SecureBuffer buff(32);
  const SecureBuffer& cbuff = buff;

  auto ok = cbuff.Subspan(0, 32);

  ASSERT_TRUE(ok.has_value());
  EXPECT_EQ(ok.value().size(), 32u);  // NOLINT(bugprone-unchecked-optional-access)

  EXPECT_FALSE(cbuff.Subspan(1, 32).has_value());
}
