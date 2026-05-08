/**
 * @file    PasswordTest.cpp
 * @brief   Unit tests for Password class
 * @author  Astatine387
 */

#include "Utils/Password.h"

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>

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
 * @brief   Verify setData works with C-style string and length
 */
TEST(PasswordTest, SetDataCString) {
  Password pw;
  const char* data = "password";
  size_t size = strlen(data);

  pw.SetData(data, size);

  EXPECT_FALSE(pw.IsEmpty());
  EXPECT_STREQ(pw.GetData(), data);
  EXPECT_EQ(pw.GetSize(), size);
  EXPECT_NE(pw.GetData(), data);
}

/**
 * @brief   Verify setData works with another Password
 */
TEST(PasswordTest, SetDataPassword) {
  Password pw0;
  const char* data = "password";
  size_t size = strlen(data);

  pw0.SetData(data, size);

  Password pw1;

  pw1.SetData(pw0);

  EXPECT_FALSE(pw1.IsEmpty());
  EXPECT_STREQ(pw1.GetData(), data);
  EXPECT_EQ(pw1.GetSize(), size);
  EXPECT_NE(pw1.GetData(), pw0.GetData());
}

/**
 * @brief   Verify setData replaces existing data
 */
TEST(PasswordTest, SetDataReplace) {
  Password pw;

  const char* data0 = "qwerty1234";
  const char* data1 = "password";
  size_t size0 = strlen(data0);
  size_t size1 = strlen(data1);

  pw.SetData(data0, size0);
  pw.SetData(data1, size1);

  EXPECT_STREQ(pw.GetData(), data1);
  EXPECT_EQ(pw.GetSize(), size1);
}

/* ==================================================
 * Copy and Move Operators Test
 * ================================================== */

/**
 * @brief   Verify copy constructor performs deep copy
 *
 * Deep copy means identical values, but different memory addresses
 */
TEST(PasswordTest, CopyConstructor) {
  Password pw0;

  const char* data = "password";
  size_t size = strlen(data);

  pw0.SetData(data, size);

  Password pw1(pw0);

  EXPECT_STREQ(pw0.GetData(), pw1.GetData());
  EXPECT_EQ(pw0.GetSize(), pw1.GetSize());
  EXPECT_NE(pw0.GetData(), pw1.GetData());
}

/**
 * @brief   Verify copy assignment performs deep copy
 *
 * Deep copy means identical values, but different memory addresses
 */
TEST(PasswordTest, CopyAssignment) {
  Password pw0, pw1;

  const char* data0 = "qwerty1234";
  const char* data1 = "password";
  size_t size0 = strlen(data0);
  size_t size1 = strlen(data1);

  pw0.SetData(data0, size0);
  pw1.SetData(data1, size1);

  pw1 = pw0;

  EXPECT_STREQ(pw1.GetData(), data0);
  EXPECT_EQ(pw1.GetSize(), size0);
  EXPECT_NE(pw0.GetData(), pw1.GetData());
}

/**
 * @brief   Verify move constructor transfers ownership
 *
 * After move, destination must own the original pointer, and source must be empty
 */
TEST(PasswordTest, MoveConstructor) {
  Password pw0;
  const char* data = "password";
  size_t size = strlen(data);

  pw0.SetData(data, size);

  const char* ptr = pw0.GetData();
  Password pw1(std::move(pw0));

  EXPECT_STREQ(pw1.GetData(), data);
  EXPECT_EQ(pw1.GetData(), ptr);
  EXPECT_TRUE(pw0.IsEmpty());
}

/**
 * @brief   Verify move assignment transfers ownership
 *
 * After move, destination must own the original pointer, and source must be empty
 */
TEST(PasswordTest, MoveAssignment) {
  Password pw0;
  const char* data = "password";
  size_t size = strlen(data);

  pw0.SetData(data, size);

  const char* ptr = pw0.GetData();
  Password pw1;

  pw1 = std::move(pw0);

  EXPECT_STREQ(pw1.GetData(), data);
  EXPECT_EQ(pw1.GetData(), ptr);
  EXPECT_TRUE(pw0.IsEmpty());
}

/* ==================================================
 * Safety Test
 * ================================================== */

/**
 * @brief   Verify self-assignment is handled safely
 */
TEST(PasswordTest, SelfAssignmentSafe) {
  Password pw;
  const char* data = "password";
  size_t size = strlen(data);

  pw.SetData(data, size);

  pw = pw;

  EXPECT_STREQ(pw.GetData(), data);
  EXPECT_EQ(pw.GetSize(), size);
}

/**
 * @brief   Verify null pointer is handled safely
 */
TEST(PasswordTest, SetDataNull) {
  Password pw;
  pw.SetData(nullptr, 0);

  EXPECT_TRUE(pw.IsEmpty());
}

/**
 * @brief   Verify destructor is called without crash after move
 */
TEST(PasswordTest, DestructorAfterMove) {
  Password* pw0 = new Password();
  const char* data = "password";
  size_t size = strlen(data);

  pw0->SetData(data, size);

  Password pw1(std::move(*pw0));

  EXPECT_NO_THROW(delete pw0);
  EXPECT_STREQ(pw1.GetData(), data);
}