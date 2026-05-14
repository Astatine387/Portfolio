/**
 * @file    PasswordTest.cpp
 * @brief   Unit tests for Password class
 * @author  Astatine387
 */

#include "Utils/Password.h"

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>

#include "Common/constants.h"

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

  const char* orig_ptr = pw0.GetData();

  Password pw1(std::move(pw0));

  EXPECT_STREQ(pw1.GetData(), data);
  EXPECT_EQ(pw1.GetSize(), size);
  EXPECT_EQ(pw1.GetData(), orig_ptr);
  EXPECT_TRUE(pw0.IsEmpty());
  EXPECT_EQ(pw0.GetData(), nullptr);
}

/**
 * @brief   Verify move assignment transfers ownership
 *
 * After move, destination must own the original pointer, and source must be empty
 */
TEST(PasswordTest, MoveAssignment) {
  Password pw0, pw1;
  const char* data0 = "qwerty1234";
  const char* data1 = "password";
  size_t size0 = strlen(data0);
  size_t size1 = strlen(data1);

  pw0.SetData(data0, size0);
  pw1.SetData(data1, size1);

  const char* orig_ptr = pw0.GetData();

  pw1 = std::move(pw0);

  EXPECT_STREQ(pw1.GetData(), data0);
  EXPECT_EQ(pw1.GetSize(), size0);
  EXPECT_EQ(pw1.GetData(), orig_ptr);
  EXPECT_TRUE(pw0.IsEmpty());
  EXPECT_EQ(pw0.GetData(), nullptr);
}

/**
 * @brief   Verify copy constructor from empty password produces empty password
 */
TEST(PasswordTest, CopyConstructorEmpty) {
  Password pw0;
  Password pw1(pw0);

  EXPECT_TRUE(pw1.IsEmpty());
  EXPECT_EQ(pw1.GetData(), nullptr);
}

/**
 * @brief   Verify self-assignment does not corrupt data
 */
TEST(PasswordTest, SelfAssignment) {
  Password pw;
  const char* data = "password";
  size_t size = strlen(data);

  pw.SetData(data, size);

  pw = pw;

  EXPECT_STREQ(pw.GetData(), data);
  EXPECT_EQ(pw.GetSize(), size);
}

/* ==================================================
 * Compare Test
 * ================================================== */

/**
 * @brief   Verify compare returns true for identical passwords
 */
TEST(PasswordTest, CompareEqual) {
  Password pw0, pw1;
  const char* data = "password";
  size_t size = strlen(data);

  pw0.SetData(data, size);
  pw1.SetData(data, size);

  EXPECT_TRUE(pw0.Equal(pw1));
  EXPECT_TRUE(pw1.Equal(pw0));
}

/**
 * @brief   Verify compare returns false for different passwords
 */
TEST(PasswordTest, CompareDifferent) {
  Password pw0, pw1;
  const char* data0 = "password";
  const char* data1 = "qwerty1234";
  size_t size0 = strlen(data0);
  size_t size1 = strlen(data1);

  pw0.SetData(data0, size0);
  pw1.SetData(data1, size1);

  EXPECT_FALSE(pw0.Equal(pw1));
  EXPECT_FALSE(pw1.Equal(pw0));
}

/**
 * @brief   Verify compare returns false for same-length but different passwords
 */
TEST(PasswordTest, CompareSameLenDifferent) {
  Password pw0, pw1;
  const char* data0 = "password";
  const char* data1 = "asdf1234";
  size_t size0 = strlen(data0);
  size_t size1 = strlen(data1);

  pw0.SetData(data0, size0);
  pw1.SetData(data1, size1);

  EXPECT_FALSE(pw0.Equal(pw1));
}

/**
 * @brief   Verify compare returns false when one password is empty
 */
TEST(PasswordTest, CompareWithEmpty) {
  Password pw0, pw1;
  const char* data = "password";
  size_t size = strlen(data);

  pw0.SetData(data, size);

  EXPECT_FALSE(pw0.Equal(pw1));
}

/* ==================================================
 * Clean Test
 * ================================================== */

/**
 * @brief   Verify clean wipes password data
 */
TEST(PasswordTest, Clean) {
  Password pw;
  const char* data = "password";
  size_t size = strlen(data);

  pw.SetData(data, size);
  pw.Clean();

  EXPECT_TRUE(pw.IsEmpty());
  EXPECT_EQ(pw.GetSize(), 0);
  EXPECT_EQ(pw.GetData(), nullptr);
}

/**
 * @brief   Verify clean on empty password does not crash
 */
TEST(PasswordTest, CleanEmpty) {
  Password pw;

  pw.Clean();

  EXPECT_TRUE(pw.IsEmpty());
}

/* ==================================================
 * MAX_SIZE Test
 * ================================================== */

/**
 * @brief   Verify setData succeeds at exactly MAX_SIZE
 */
TEST(PasswordTest, SetDataMaxSize) {
  Password pw;
  std::string data(kMaxPWLen, 'a');

  EXPECT_EQ(pw.SetData(data.c_str(), data.size()), 0);
  EXPECT_EQ(pw.GetSize(), kMaxPWLen);
}

/**
 * @brief   Verify setData rejects data exceeding MAX_SIZE
 */
TEST(PasswordTest, SetDataExceedsMaxSize) {
  Password pw;
  std::string data(kMaxPWLen + 1, 'a');

  EXPECT_EQ(pw.SetData(data.c_str(), data.size()), 1);
  EXPECT_TRUE(pw.IsEmpty());
}