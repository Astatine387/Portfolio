/**
 * @file    PasswordTest.cpp
 * @brief   Unit tests for Password class
 * @author  Astatine387
 */

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

    const char *ptr = pw0.getData();
    Password pw1(std::move(pw0));
    
    EXPECT_STREQ(pw1.getData(), data);
    EXPECT_EQ(pw1.getData(), ptr);
    EXPECT_TRUE(pw0.isEmpty());
}

/**
 * @brief   Verify move assignment transfers ownership
 * 
 * After move, destination must own the original pointer, and source must be empty
 */
TEST(PasswordTest, MoveAssignment) {
    Password pw0;
    const char *data = "password";
    size_t size = strlen(data);

    pw0.setData(data, size);

    const char *ptr = pw0.getData();
    Password pw1;

    pw1 = std::move(pw0);

    EXPECT_STREQ(pw1.getData(), data);
    EXPECT_EQ(pw1.getData(), ptr);
    EXPECT_TRUE(pw0.isEmpty());
}


/* ==================================================
 * Safety Test
 * ================================================== */

/**
 * @brief   Verify self-assignment is handled safely
 */
TEST(PasswordTest, SelfAssignmentSafe) {
    Password pw;
    const char *data = "password";
    size_t size = strlen(data);

    pw.setData(data, size);

    pw = pw;

    EXPECT_STREQ(pw.getData(), data);
    EXPECT_EQ(pw.getSize(), size);
}

/**
 * @brief   Verify null pointer is handled safely
 */
TEST(PasswordTest, SetDataNull) {
    Password pw;
    pw.setData(nullptr, 0);

    EXPECT_TRUE(pw.isEmpty());
}

/**
 * @brief   Verify destructor is called without crash after move
 */
TEST(PasswordTest, DestructorAfterMove) {
    Password *pw0 = new Password();
    const char *data = "password";
    size_t size = strlen(data);

    pw0->setData(data, size);

    Password pw1(std::move(*pw0));

    EXPECT_NO_THROW(delete pw0);
    EXPECT_STREQ(pw1.getData(), data);
}