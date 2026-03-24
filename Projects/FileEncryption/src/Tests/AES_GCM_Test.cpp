/**
 * @file    AES_GCM_Test.cpp
 * @brief   Unit tests for AES-GCM class
 * @author  Astatine387
 */

#include "Core/AES_GCM.h"
#include "Utils/library.h"
#include <QString>
#include <gtest/gtest.h>


/**
 * @class   AES_GCM_Test
 * @brief   Test fixture for AES_GCM encryption/decryption tests
 */
class AES_GCM_Test : public ::testing::Test {
protected:
    QString srcPath = "test_src.tmp";
    QString encPath = "test_enc.tmp";
    QString decPath = "test_dec.tmp";

    /**
     * @brief   Clean up temporary files after each test
     */
    void TearDown() override {
        RemoveFile(srcPath);
        RemoveFile(encPath);
        RemoveFile(decPath);
    }

    /**
     * @brief   Create test file
     * @param   path    File path
     * @param   data    File content
     * @param   size    File size
     */
    void create(QString &path, std::vector<uint8_t> &data, int size) {
        FILE *file = nullptr;

        OpenFile(&file, path, "wb");

        if (file) {
            fwrite(data.data(), sizeof(uint8_t), size, file);
            fclose(file);
        }
    }

    /**
     * @brief   Read file into buffer
     * @param   path    Source file path
     * @param   vec     Destination buffer
     */
    void read(QString &path, std::vector<uint8_t> &vec) {
        FILE *file = nullptr;
        uint64_t size;

        OpenFile(&file, path, "rb");

        if (!file) return;

        size = GetFileSize(file);

        vec.resize(size);

        fread(vec.data(), sizeof(uint8_t), size, file);

        fclose(file);
    }
};


/* ==================================================
 * Encryption/Decryption Tests
 * ================================================== */

/**
 * @brief   Verify encryption and decryption works with no error, and decrypted data is identical to original
 */
TEST_F(AES_GCM_Test, EncryptDecryptBasic) {
    AES_GCM aes;
    FILE *src = nullptr, *dst = nullptr;
    std::vector<uint8_t> orig, copy;
    const char *data = "Hello, world!";
    const char *pw = "password";
    int dsize = strlen(data);
    int psize = strlen(pw);
    int res;

    for (int i = 0; i < dsize; i++) orig.push_back(data[i]);
    
    create(srcPath, orig, dsize);

    
    /* Encrypt */

    OpenFile(&src, srcPath, "rb");
    OpenFile(&dst, encPath, "wb+");

    res = aes.encrypt(src, dst, pw, psize);

    if (src) fclose(src);
    if (dst) fclose(dst);

    EXPECT_EQ(res, 0);


    /* Decrypt */

    OpenFile(&src, encPath, "rb");
    OpenFile(&dst, decPath, "wb+");

    res = aes.decrypt(src, dst, pw, psize);

    if (src) fclose(src);
    if (dst) fclose(dst);

    EXPECT_EQ(res, 0);


    /* Compare with original */

    read(decPath, copy);

    EXPECT_EQ(orig, copy);
}


/* ==================================================
 * Authentication Tests
 * ================================================== */

/**
 * @brief   Verify decryption fails with wrong password
 */
TEST_F(AES_GCM_Test, WrongPasswordFails) {
    AES_GCM aes;
    FILE *src = nullptr, *dst = nullptr;
    std::vector<uint8_t> orig;
    const char *data = "Hello, world!";
    const char *pw0 = "password", *pw1 = "asdf1234";
    int dsize = strlen(data);
    int psize0 = strlen(pw0), psize1 = strlen(pw1);
    int res;

    for (int i = 0; i < dsize; i++) orig.push_back(data[i]);

    create(srcPath, orig, dsize);


    /* Encrypt */

    OpenFile(&src, srcPath, "rb");
    OpenFile(&dst, encPath, "wb+");

    aes.encrypt(src, dst, pw0, psize0);

    if (src) fclose(src);
    if (dst) fclose(dst);


    /* Decrypt with wrong password */

    OpenFile(&src, encPath, "rb");
    OpenFile(&dst, decPath, "wb");

    res = aes.decrypt(src, dst, pw1, psize1);

    if (src) fclose(src);
    if (dst) fclose(dst);

    EXPECT_NE(res, 0);
}

/**
 * @brief   Verify tampered ciphertext fails decryption
 */
TEST_F(AES_GCM_Test, TamperedCipherFails) {
    AES_GCM aes;
    FILE *src = nullptr, *dst = nullptr;
    std::vector<uint8_t> orig, copy;
    const char *data = "Hello, world!";
    const char *pw = "password";
    int dsize = strlen(data);
    int psize = strlen(pw);
    int res;

    for (int i = 0; i < dsize; i++) orig.push_back(data[i]);

    create(srcPath, orig, dsize);

    
    /* Encrypt */

    OpenFile(&src, srcPath, "rb");
    OpenFile(&dst, encPath, "wb+");

    aes.encrypt(src, dst, pw, psize);

    if (src) fclose(src);
    if (dst) fclose(dst);

    
    /* Tamper ciphertext */
    
    read(encPath, copy);

    copy[kSaltSize + kIVSize] ^= 0xFF;

    create(encPath, copy, copy.size());


    /* Decrypt */

    OpenFile(&src, encPath, "rb");
    OpenFile(&dst, decPath, "wb+");

    res = aes.decrypt(src, dst, pw, psize);

    if (src) fclose(src);
    if (dst) fclose(dst);

    EXPECT_NE(res, 0);
}


/* ==================================================
 * Edge Case Tests
 * ================================================== */

/**
 * @brief   Verify empty file can be encrypted and decrypted
 */
TEST_F(AES_GCM_Test, EmptyFile) {
    AES_GCM aes;
    FILE *src = nullptr, *dst = nullptr;
    std::vector<uint8_t> orig, copy;
    const char *pw = "password";
    int dsize = 0;
    int psize = strlen(pw);
    int res;

    create(srcPath, orig, dsize);


    /* Encrypt */

    OpenFile(&src, srcPath, "rb");
    OpenFile(&dst, encPath, "wb+");

    res = aes.encrypt(src, dst, pw, psize);

    if (src) fclose(src);
    if (dst) fclose(dst);

    EXPECT_EQ(res, 0);


    /* Decrypt */

    OpenFile(&src, encPath, "rb");
    OpenFile(&dst, decPath, "wb+");

    res = aes.decrypt(src, dst, pw, psize);

    if (src) fclose(src);
    if (dst) fclose(dst);

    EXPECT_EQ(res, 0);


    /* Compare with original */

    read(decPath, copy);

    EXPECT_EQ(orig, copy);
}

/**
 * @brief   Verify file with exact buffer size works correctly
 */
TEST_F(AES_GCM_Test, ExactBuffSizeFile) {
    AES_GCM aes;
    FILE *src = nullptr, *dst = nullptr;
    std::vector<uint8_t> orig, copy;
    const char *pw = "password";
    int dsize = kBlockSize * kBuffSize;
    int psize = strlen(pw);
    int res;

    orig.resize(dsize, 'a');

    create(srcPath, orig, dsize);

    /* Encrypt */

    OpenFile(&src, srcPath, "rb");
    OpenFile(&dst, encPath, "wb+");

    res = aes.encrypt(src, dst, pw, psize);

    if (src) fclose(src);
    if (dst) fclose(dst);

    EXPECT_EQ(res, 0);


    /* Decrypt */

    OpenFile(&src, encPath, "rb");
    OpenFile(&dst, decPath, "wb+");

    res = aes.decrypt(src, dst, pw, psize);

    if (src) fclose(src);
    if (dst) fclose(dst);

    EXPECT_EQ(res, 0);


    /* Compare with original */

    read(decPath, copy);

    EXPECT_EQ(orig, copy);
}

/**
 * @brief   Verify arbitrary sized file works correctly
 */
TEST_F(AES_GCM_Test, ArbitrarySizeFile) {
    AES_GCM aes;
    FILE *src = nullptr, *dst = nullptr;
    std::vector<uint8_t> orig, copy;
    const char *pw = "password";
    int dsize = 50000;
    int psize = strlen(pw);
    int res;

    orig.resize(dsize, 'a');

    create(srcPath, orig, dsize);

    /* Encrypt */

    OpenFile(&src, srcPath, "rb");
    OpenFile(&dst, encPath, "wb+");

    res = aes.encrypt(src, dst, pw, psize);

    if (src) fclose(src);
    if (dst) fclose(dst);

    EXPECT_EQ(res, 0);


    /* Decrypt */

    OpenFile(&src, encPath, "rb");
    OpenFile(&dst, decPath, "wb+");

    res = aes.decrypt(src, dst, pw, psize);

    if (src) fclose(src);
    if (dst) fclose(dst);

    EXPECT_EQ(res, 0);


    /* Compare with original */

    read(decPath, copy);

    EXPECT_EQ(orig, copy);
}


/* ==================================================
 * Callback Tests
 * ================================================== */

/**
 * @brief   Verify progress callback is invoked during encryption
 */
TEST_F(AES_GCM_Test, ProgressCallback) {
    AES_GCM aes;
    FILE *src = nullptr, *dst = nullptr;
    std::vector<uint8_t> orig;
    const char *pw = "password";
    int dsize = kBlockSize * kBuffSize * 10;
    int psize = strlen(pw);
    int cnt = 0, last = -1;

    orig.resize(dsize, 'a');

    create(srcPath, orig, dsize);


    /* Encrypt with progress callback */

    OpenFile(&src, srcPath, "rb");
    OpenFile(&dst, encPath, "wb+");

    aes.setProgressCb([&](int perc, bool *cancelled) {
        cnt++;

        EXPECT_GE(perc, last);

        last = perc;
    });

    aes.encrypt(src, dst, pw, psize);

    if (src) fclose(src);
    if (dst) fclose(dst);

    EXPECT_GT(cnt, 0);
}

/**
 * @brief   Verify error callback is invoked on failure
 */
TEST_F(AES_GCM_Test, ErrorCallback) {
    AES_GCM aes;
    FILE *src = nullptr, *dst = nullptr;
    std::vector<uint8_t> orig;
    bool b = false;
    const char *data = "Hello, world!";
    const char *pw0 = "password", *pw1 = "asdf1234";
    int dsize = strlen(data);
    int psize0 = strlen(pw0), psize1 = strlen(pw1);

    for (int i = 0; i < dsize; i++) orig.push_back(data[i]);

    create(srcPath, orig, dsize);


    /* Encrypt */

    OpenFile(&src, srcPath, "rb");
    OpenFile(&dst, encPath, "wb+");

    aes.encrypt(src, dst, pw0, psize0);

    if (src) fclose(src);
    if (dst) fclose(dst);


    /* Decrypt with wrong password and error callback */

    OpenFile(&src, encPath, "rb");
    OpenFile(&dst, decPath, "wb+");

    aes.setErrorCb([&](const char *msg) {
        b = true;
    });

    aes.decrypt(src, dst, pw1, psize1);

    if (src) fclose(src);
    if (dst) fclose(dst);

    EXPECT_TRUE(b);
}


/* ==================================================
 * Cancellation Tests
 * ================================================== */

/**
 * @brief   Verify cancellation works
 */
TEST_F(AES_GCM_Test, Cancellation) {
    AES_GCM aes;
    FILE *src = nullptr, *dst = nullptr;
    std::vector<uint8_t> orig;
    const char *pw = "password";
    int dsize = kBlockSize * kBuffSize * 10;
    int psize = strlen(pw);
    int cnt = 0, res;

    orig.resize(dsize, 'a');

    create(srcPath, orig, dsize);


    /* Encrypt and cancel after the second callback */

    OpenFile(&src, srcPath, "rb");
    OpenFile(&dst, encPath, "wb+");

    aes.setProgressCb([&](int perc, bool *cancelled) {
        cnt++;

        if (cnt >= 2) *cancelled = true;
    });

    res = aes.encrypt(src, dst, pw, psize);

    if (src) fclose(src);
    if (dst) fclose(dst);

    EXPECT_NE(res, 0);
    EXPECT_GE(cnt, 2);
    EXPECT_LE(cnt, 3);
}