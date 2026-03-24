/**
 * @file    AES_GCM_Test.cpp
 * @brief   Unit tests for AES_GCM class
 * @author  Astatine387
 */

#include "Core/AES_GCM.h"
#include <gtest/gtest.h>


/* ==================================================
 * Encryption/Decryption Tests
 * ================================================== */

/**
 * @brief   Verify encryption and decryption round-trip preserves data
 */
TEST(AES_GCM_Test, EncryptDecryptBasic) {
    AES_GCM aes;

    const char *data = "Hello, world!";
    const char *pw = "password";

    size_t dsize = strlen(data);
    size_t psize = strlen(pw);
    size_t encSize = kSaltSize + kIVSize + dsize + kTagSize;

    std::vector<uint8_t> src(dsize);
    std::vector<uint8_t> enc(encSize);
    std::vector<uint8_t> dec(dsize);

    memcpy(src.data(), data, dsize);


    /* Encrypt */

    int res = aes.encrypt(src.data(), enc.data(), dsize, pw, psize);

    EXPECT_EQ(res, 0);


    /* Decrypt */

    res = aes.decrypt(enc.data(), dec.data(), encSize, pw, psize);

    EXPECT_EQ(res, 0);
    EXPECT_EQ(memcmp(src.data(), dec.data(), dsize), 0);
}

/**
 * @brief   Verify encryption produces different ciphertext each time (random salt/IV)
 */
TEST(AES_GCM_Test, EncryptProducesDifferentOutput) {
    AES_GCM aes;

    const char *data = "Hello, world!";
    const char *pw = "password";

    size_t dsize = strlen(data);
    size_t psize = strlen(pw);
    size_t encSize = kSaltSize + kIVSize + dsize + kTagSize;

    std::vector<uint8_t> src(dsize);
    std::vector<uint8_t> enc0(encSize);
    std::vector<uint8_t> enc1(encSize);

    memcpy(src.data(), data, dsize);

    aes.encrypt(src.data(), enc0.data(), dsize, pw, psize);
    aes.encrypt(src.data(), enc1.data(), dsize, pw, psize);

    EXPECT_NE(memcmp(enc0.data(), enc1.data(), encSize), 0);
}

/**
 * @brief   Verify decryption with wrong password fails
 */
TEST(AES_GCM_Test, DecryptWrongPassword) {
    AES_GCM aes;

    const char *data = "Hello, world!";
    const char *pw0 = "password";
    const char *pw1 = "asdf1234";

    size_t dsize = strlen(data);
    size_t psize0 = strlen(pw0);
    size_t psize1 = strlen(pw1);
    size_t encSize = kSaltSize + kIVSize + dsize + kTagSize;

    std::vector<uint8_t> src(dsize);
    std::vector<uint8_t> enc(encSize);
    std::vector<uint8_t> dec(dsize);

    memcpy(src.data(), data, dsize);

    aes.encrypt(src.data(), enc.data(), dsize, pw0, psize0);

    int res = aes.decrypt(enc.data(), dec.data(), encSize, pw1, psize1);

    EXPECT_NE(res, 0);
}

/**
 * @brief   Verify tampering with ciphertext causes decryption failure
 */
TEST(AES_GCM_Test, TamperedCiphertext) {
    AES_GCM aes;

    const char *data = "Hello, world!";
    const char *pw = "password";

    size_t dsize = strlen(data);
    size_t psize = strlen(pw);
    size_t encSize = kSaltSize + kIVSize + dsize + kTagSize;

    std::vector<uint8_t> src(dsize);
    std::vector<uint8_t> enc(encSize);
    std::vector<uint8_t> dec(dsize);

    memcpy(src.data(), data, dsize);

    aes.encrypt(src.data(), enc.data(), dsize, pw, psize);


    /* Tamper with encrypted data */

    enc[kSaltSize + kIVSize] ^= 0x01;

    int res = aes.decrypt(enc.data(), dec.data(), encSize, pw, psize);

    EXPECT_NE(res, 0);
}

/**
 * @brief   Verify tampering with authentication tag causes decryption failure
 */
TEST(AES_GCM_Test, TamperedTag) {
    AES_GCM aes;

    const char *data = "Hello, world!";
    const char *pw = "password";

    size_t dsize = strlen(data);
    size_t psize = strlen(pw);
    size_t encSize = kSaltSize + kIVSize + dsize + kTagSize;

    std::vector<uint8_t> src(dsize);
    std::vector<uint8_t> enc(encSize);
    std::vector<uint8_t> dec(dsize);

    memcpy(src.data(), data, dsize);

    aes.encrypt(src.data(), enc.data(), dsize, pw, psize);


    /* Tamper with authentication tag */

    enc[encSize - 1] ^= 0x01;

    int res = aes.decrypt(enc.data(), dec.data(), encSize, pw, psize);

    EXPECT_NE(res, 0);
}


/* ==================================================
 * Edge Case Tests
 * ================================================== */

/**
 * @brief   Verify encryption and decryption works with single byte
 */
TEST(AES_GCM_Test, SingleByte) {
    AES_GCM aes;

    const char *pw = "password";

    size_t psize = strlen(pw);
    size_t dsize = 1;
    size_t encSize = kSaltSize + kIVSize + dsize + kTagSize;

    uint8_t src = 0x00;
    std::vector<uint8_t> enc(encSize);
    uint8_t dec;


    /* Encrypt */

    int res = aes.encrypt(&src, enc.data(), dsize, pw, psize);

    EXPECT_EQ(res, 0);


    /* Decrypt */

    res = aes.decrypt(enc.data(), &dec, encSize, pw, psize);

    EXPECT_EQ(res, 0);
    EXPECT_EQ(dec, src);
}

/**
 * @brief   Verify encryption and decryption works with large data
 */
TEST(AES_GCM_Test, LargeData) {
    AES_GCM aes;

    const char *pw = "password";

    size_t psize = strlen(pw);
    size_t dsize = 1024 * 1024; // 1 MiB
    size_t encSize = kSaltSize + kIVSize + dsize + kTagSize;

    std::vector<uint8_t> src(dsize, 0x00);
    std::vector<uint8_t> enc(encSize);
    std::vector<uint8_t> dec(dsize);


    /* Encrypt */

    int res = aes.encrypt(src.data(), enc.data(), dsize, pw, psize);

    EXPECT_EQ(res, 0);


    /* Decrypt */

    res = aes.decrypt(enc.data(), dec.data(), encSize, pw, psize);

    EXPECT_EQ(res, 0);
    EXPECT_EQ(memcmp(src.data(), dec.data(), dsize), 0);
}


/* ==================================================
 * Error Callback Test
 * ================================================== */

/**
 * @brief   Verify error callback is invoked on decryption failure
 */
TEST(AES_GCM_Test, ErrorCallback) {
    AES_GCM aes;
    bool callbackCalled = false;

    const char *data = "Hello, world!";
    const char *pw0 = "password";
    const char *pw1 = "asdf1234";

    size_t dsize = strlen(data);
    size_t psize0 = strlen(pw0);
    size_t psize1 = strlen(pw1);
    size_t encSize = kSaltSize + kIVSize + dsize + kTagSize;

    std::vector<uint8_t> src(dsize);
    std::vector<uint8_t> enc(encSize);
    std::vector<uint8_t> dec(dsize);

    memcpy(src.data(), data, dsize);

    aes.encrypt(src.data(), enc.data(), dsize, pw0, psize0);

    aes.setErrorCb([&](const char *msg) {
        callbackCalled = true;
    });

    aes.decrypt(enc.data(), dec.data(), encSize, pw1, psize1);

    EXPECT_TRUE(callbackCalled);
}