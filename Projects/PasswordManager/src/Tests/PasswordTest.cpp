/**
 * @file    PasswordTest.cpp
 * @brief   Unit tests for Password class
 * @author  Astatine387
 */

#include "Common/constants.h"
#include "Utils/Password.h"
#include <cstdint>
#include <cstddef>
#include <gtest/gtest.h>


/* ==================================================
 * Construction and Initialization Test
 * ================================================== */

/**
 * @brief   Verify default constructor creates empty password
 */
TEST(PasswordTest, IsDefaultEmpty) {
    Password pw;

    EXPECT_TRUE(pw.isEmpty());
    EXPECT_EQ(pw.getSize(), 0);
    EXPECT_EQ(pw.getData(), nullptr);
}


/* ==================================================
 * Setting Data Test
 * ================================================== */

/**
 * @brief   Verify setData works with C-style string and length
 */
TEST(PasswordTest, SetDataCString) {
    Password pw;
    const char *data = "password";
    size_t size = strlen(data);

    pw.setData(data, size);

    EXPECT_FALSE(pw.isEmpty());
    EXPECT_STREQ(pw.getData(), data);
    EXPECT_EQ(pw.getSize(), size);
    EXPECT_NE(pw.getData(), data);
}

/**
 * @brief   Verify setData works with another Password
 */
TEST(PasswordTest, SetDataPassword) {
    Password pw0;
    const char *data = "password";
    size_t size = strlen(data);

    pw0.setData(data, size);

    Password pw1;

    pw1.setData(pw0);

    EXPECT_FALSE(pw1.isEmpty());
    EXPECT_STREQ(pw1.getData(), data);
    EXPECT_EQ(pw1.getSize(), size);
    EXPECT_NE(pw1.getData(), pw0.getData());
}

/**
 * @brief   Verify setData replaces existing data
 */
TEST(PasswordTest, SetDataReplace) {
    Password pw;

    const char *data0 = "qwerty1234";
    const char *data1 = "password";
    size_t size0 = strlen(data0);
    size_t size1 = strlen(data1);

    pw.setData(data0, size0);
    pw.setData(data1, size1);

    EXPECT_STREQ(pw.getData(), data1);
    EXPECT_EQ(pw.getSize(), size1);
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

    const char *data = "password";
    size_t size = strlen(data);

    pw0.setData(data, size);

    Password pw1(pw0);

    EXPECT_STREQ(pw0.getData(), pw1.getData());
    EXPECT_EQ(pw0.getSize(), pw1.getSize());
    EXPECT_NE(pw0.getData(), pw1.getData());
}

/**
 * @brief   Verify copy assignment performs deep copy
 *
 * Deep copy means identical values, but different memory addresses
 */
TEST(PasswordTest, CopyAssignment) {
    Password pw0, pw1;

    const char *data0 = "qwerty1234";
    const char *data1 = "password";
    size_t size0 = strlen(data0);
    size_t size1 = strlen(data1);

    pw0.setData(data0, size0);
    pw1.setData(data1, size1);

    pw1 = pw0;

    EXPECT_STREQ(pw1.getData(), data0);
    EXPECT_EQ(pw1.getSize(), size0);
    EXPECT_NE(pw0.getData(), pw1.getData());
}

/**
 * @brief   Verify move constructor transfers ownership
 *
 * After move, destination must own the original pointer, and source must be empty
 */
TEST(PasswordTest, MoveConstructor) {
    Password pw0;
    const char *data = "password";
    size_t size = strlen(data);

    pw0.setData(data, size);

    const char *origPtr = pw0.getData();

    Password pw1(std::move(pw0));

    EXPECT_STREQ(pw1.getData(), data);
    EXPECT_EQ(pw1.getSize(), size);
    EXPECT_EQ(pw1.getData(), origPtr);
    EXPECT_TRUE(pw0.isEmpty());
    EXPECT_EQ(pw0.getData(), nullptr);
}

/**
 * @brief   Verify move assignment transfers ownership
 *
 * After move, destination must own the original pointer, and source must be empty
 */
TEST(PasswordTest, MoveAssignment) {
    Password pw0, pw1;
    const char *data0 = "qwerty1234";
    const char *data1 = "password";
    size_t size0 = strlen(data0);
    size_t size1 = strlen(data1);

    pw0.setData(data0, size0);
    pw1.setData(data1, size1);

    const char *origPtr = pw0.getData();

    pw1 = std::move(pw0);

    EXPECT_STREQ(pw1.getData(), data0);
    EXPECT_EQ(pw1.getSize(), size0);
    EXPECT_EQ(pw1.getData(), origPtr);
    EXPECT_TRUE(pw0.isEmpty());
    EXPECT_EQ(pw0.getData(), nullptr);
}

/**
 * @brief   Verify copy constructor from empty password produces empty password
 */
TEST(PasswordTest, CopyConstructorEmpty) {
    Password pw0;
    Password pw1(pw0);

    EXPECT_TRUE(pw1.isEmpty());
    EXPECT_EQ(pw1.getData(), nullptr);
}

/**
 * @brief   Verify self-assignment does not corrupt data
 */
TEST(PasswordTest, SelfAssignment) {
    Password pw;
    const char *data = "password";
    size_t size = strlen(data);

    pw.setData(data, size);

    pw = pw;

    EXPECT_STREQ(pw.getData(), data);
    EXPECT_EQ(pw.getSize(), size);
}


/* ==================================================
 * Compare Test
 * ================================================== */

/**
 * @brief   Verify compare returns true for identical passwords
 */
TEST(PasswordTest, CompareEqual) {
    Password pw0, pw1;
    const char *data = "password";
    size_t size = strlen(data);

    pw0.setData(data, size);
    pw1.setData(data, size);

    EXPECT_TRUE(pw0.equal(pw1));
    EXPECT_TRUE(pw1.equal(pw0));
}

/**
 * @brief   Verify compare returns false for different passwords
 */
TEST(PasswordTest, CompareDifferent) {
    Password pw0, pw1;
    const char *data0 = "password";
    const char *data1 = "qwerty1234";
    size_t size0 = strlen(data0);
    size_t size1 = strlen(data1);

    pw0.setData(data0, size0);
    pw1.setData(data1, size1);

    EXPECT_FALSE(pw0.equal(pw1));
    EXPECT_FALSE(pw1.equal(pw0));
}

/**
 * @brief   Verify compare returns false for same-length but different passwords
 */
TEST(PasswordTest, CompareSameLenDifferent) {
    Password pw0, pw1;
    const char *data0 = "password";
    const char *data1 = "asdf1234";
    size_t size0 = strlen(data0);
    size_t size1 = strlen(data1);

    pw0.setData(data0, size0);
    pw1.setData(data1, size1);

    EXPECT_FALSE(pw0.equal(pw1));
}

/**
 * @brief   Verify compare returns false when one password is empty
 */
TEST(PasswordTest, CompareWithEmpty) {
    Password pw0, pw1;
    const char *data = "password";
    size_t size = strlen(data);

    pw0.setData(data, size);

    EXPECT_FALSE(pw0.equal(pw1));
}


/* ==================================================
 * Clean Test
 * ================================================== */

/**
 * @brief   Verify clean wipes password data
 */
TEST(PasswordTest, Clean) {
    Password pw;
    const char *data = "password";
    size_t size = strlen(data);

    pw.setData(data, size);
    pw.clean();

    EXPECT_TRUE(pw.isEmpty());
    EXPECT_EQ(pw.getSize(), 0);
    EXPECT_EQ(pw.getData(), nullptr);
}

/**
 * @brief   Verify clean on empty password does not crash
 */
TEST(PasswordTest, CleanEmpty) {
    Password pw;

    pw.clean();

    EXPECT_TRUE(pw.isEmpty());
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

    EXPECT_EQ(pw.setData(data.c_str(), data.size()), 0);
    EXPECT_EQ(pw.getSize(), kMaxPWLen);
}

/**
 * @brief   Verify setData rejects data exceeding MAX_SIZE
 */
TEST(PasswordTest, SetDataExceedsMaxSize) {
    Password pw;
    std::string data(kMaxPWLen + 1, 'a');

    EXPECT_EQ(pw.setData(data.c_str(), data.size()), 1);
    EXPECT_TRUE(pw.isEmpty());
}