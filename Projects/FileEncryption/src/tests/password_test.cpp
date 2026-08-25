/**
 * @file    password_test.cpp
 * @brief   Unit tests for Password class
 * @author  Astatine387
 */

#include "utils/password.h"

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <type_traits>
#include <utility>

/* ==================================================
 * Construction and Initialization Test
 * ================================================== */

/**
 * @brief   Verify default constructor creates empty password
 */
TEST(PasswordTest, IsDefaultEmpty) {
  Password pw;

  EXPECT_TRUE(pw.IsEmpty());
  EXPECT_EQ(pw.GetSize(), 0);
  EXPECT_EQ(pw.GetData(), nullptr);
}

/* ==================================================
 * Setting Data Test
 * ================================================== */

/**
 * @brief   Verify SetData works with C-style string and length
 */
TEST(PasswordTest, SetDataCString) {
  Password pw;
  const char* data = "password";
  size_t size = strlen(data);

  ASSERT_EQ(pw.SetData(data, size), Result::kSuccess);

  EXPECT_FALSE(pw.IsEmpty());
  EXPECT_STREQ(pw.GetData(), data);
  EXPECT_EQ(pw.GetSize(), size);
  EXPECT_NE(pw.GetData(), data);
}

/**
 * @brief   Verify SetData works with another Password
 */
TEST(PasswordTest, SetDataPassword) {
  Password pw0;
  const char* data = "password";
  size_t size = strlen(data);

  ASSERT_EQ(pw0.SetData(data, size), Result::kSuccess);

  Password pw1;

  ASSERT_EQ(pw1.SetData(pw0), Result::kSuccess);

  EXPECT_FALSE(pw1.IsEmpty());
  EXPECT_STREQ(pw1.GetData(), data);
  EXPECT_EQ(pw1.GetSize(), size);
  EXPECT_NE(pw1.GetData(), pw0.GetData());
}

/**
 * @brief   Verify SetData replaces existing data
 */
TEST(PasswordTest, SetDataReplace) {
  Password pw;

  const char* data0 = "qwerty1234";
  const char* data1 = "password";
  size_t size0 = strlen(data0);
  size_t size1 = strlen(data1);

  ASSERT_EQ(pw.SetData(data0, size0), Result::kSuccess);
  ASSERT_EQ(pw.SetData(data1, size1), Result::kSuccess);

  EXPECT_STREQ(pw.GetData(), data1);
  EXPECT_EQ(pw.GetSize(), size1);
}

/* ==================================================
 * Copy and Move Operators Test
 * ================================================== */

/**
 * @brief   Verify Password is move-only
 *
 * A copy allocates locked memory and can fail, and a constructor cannot report
 * that failure, so copying is deleted in favour of SetData(const Password&)
 */
TEST(PasswordTest, IsMoveOnly) {
  static_assert(!std::is_copy_constructible_v<Password>, "Password must not be copy constructible");
  static_assert(!std::is_copy_assignable_v<Password>, "Password must not be copy assignable");
  static_assert(std::is_move_constructible_v<Password>, "Password must be move constructible");
  static_assert(std::is_move_assignable_v<Password>, "Password must be move assignable");
  static_assert(std::is_nothrow_move_constructible_v<Password>, "Password move must be noexcept");
  static_assert(std::is_nothrow_move_assignable_v<Password>, "Password move must be noexcept");

  SUCCEED();
}

/**
 * @brief   Verify the checked copy performs a deep copy
 *
 * Deep copy means identical values, but different memory addresses
 */
TEST(PasswordTest, CheckedCopyIsDeep) {
  Password pw0, pw1;

  const char* data0 = "qwerty1234";
  const char* data1 = "password";
  size_t size0 = strlen(data0);
  size_t size1 = strlen(data1);

  ASSERT_EQ(pw0.SetData(data0, size0), Result::kSuccess);
  ASSERT_EQ(pw1.SetData(data1, size1), Result::kSuccess);

  ASSERT_EQ(pw1.SetData(pw0), Result::kSuccess);

  EXPECT_STREQ(pw1.GetData(), data0);
  EXPECT_EQ(pw1.GetSize(), size0);
  EXPECT_NE(pw0.GetData(), pw1.GetData());
}

/**
 * @brief   Verify move constructor transfers ownership
 *
 * After move, destination must own the original pointer, and source must be
 * empty
 */
TEST(PasswordTest, MoveConstructor) {
  Password pw0;
  const char* data = "password";
  size_t size = strlen(data);

  ASSERT_EQ(pw0.SetData(data, size), Result::kSuccess);

  const char* orig_ptr = pw0.GetData();

  Password pw1(std::move(pw0));

  EXPECT_STREQ(pw1.GetData(), data);
  EXPECT_EQ(pw1.GetSize(), size);
  EXPECT_EQ(pw1.GetData(), orig_ptr);
  EXPECT_TRUE(pw0.IsEmpty());         // NOLINT(bugprone-use-after-move)
  EXPECT_EQ(pw0.GetData(), nullptr);  // NOLINT(clang-analyzer-cplusplus.Move)
}

/**
 * @brief   Verify move assignment transfers ownership
 *
 * After move, destination must own the original pointer, and source must be
 * empty
 */
TEST(PasswordTest, MoveAssignment) {
  Password pw0, pw1;
  const char* data0 = "qwerty1234";
  const char* data1 = "password";
  size_t size0 = strlen(data0);
  size_t size1 = strlen(data1);

  ASSERT_EQ(pw0.SetData(data0, size0), Result::kSuccess);
  ASSERT_EQ(pw1.SetData(data1, size1), Result::kSuccess);

  const char* orig_ptr = pw0.GetData();

  pw1 = std::move(pw0);

  EXPECT_STREQ(pw1.GetData(), data0);
  EXPECT_EQ(pw1.GetSize(), size0);
  EXPECT_EQ(pw1.GetData(), orig_ptr);
  EXPECT_TRUE(pw0.IsEmpty());         // NOLINT(bugprone-use-after-move)
  EXPECT_EQ(pw0.GetData(), nullptr);  // NOLINT(clang-analyzer-cplusplus.Move)
}

/* ==================================================
 * Safety Test
 * ================================================== */

/**
 * @brief   Verify a self-copy through SetData does not touch freed memory
 */
TEST(PasswordTest, SetDataSelf) {
  Password pw;
  const char* data = "password";
  size_t size = strlen(data);

  ASSERT_EQ(pw.SetData(data, size), Result::kSuccess);

  const char* orig_ptr = pw.GetData();

  EXPECT_EQ(pw.SetData(pw), Result::kSuccess);

  EXPECT_STREQ(pw.GetData(), data);
  EXPECT_EQ(pw.GetSize(), size);
  EXPECT_EQ(pw.GetData(), orig_ptr);
}

/**
 * @brief   Verify self-move leaves the object usable
 */
TEST(PasswordTest, SelfMoveAssignment) {
  Password pw;
  const char* data = "password";
  size_t size = strlen(data);

  ASSERT_EQ(pw.SetData(data, size), Result::kSuccess);

  Password& alias = pw;

  pw = std::move(alias);

  EXPECT_STREQ(pw.GetData(), data);  // NOLINT(bugprone-use-after-move)
  EXPECT_EQ(pw.GetSize(), size);
}

/**
 * @brief   Verify null pointer is handled safely
 */
TEST(PasswordTest, SetDataNull) {
  Password pw;

  EXPECT_EQ(pw.SetData(nullptr, 0), Result::kSuccess);
  EXPECT_TRUE(pw.IsEmpty());
}

/**
 * @brief   Verify destructor is called without crash after move
 */
TEST(PasswordTest, DestructorAfterMove) {
  Password* pw0 = new Password();
  const char* data = "password";
  size_t size = strlen(data);

  ASSERT_EQ(pw0->SetData(data, size), Result::kSuccess);

  Password pw1(std::move(*pw0));

  EXPECT_NO_THROW(delete pw0);
  EXPECT_STREQ(pw1.GetData(), data);
}
