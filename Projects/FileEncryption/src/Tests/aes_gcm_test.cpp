/**
 * @file    aes_gcm_test.cpp
 * @brief   Unit tests for AES-GCM class
 * @author  Astatine387
 */

#include "Core/aes_gcm.h"

#include <gtest/gtest.h>

#include <string>

#include "Utils/platform.h"

/**
 * @class   TEST
 * @brief   Test fixture for AesGcm encryption/decryption tests
 */
class TEST : public ::testing::Test {
 protected:
  std::string src_path_ = "test_src.tmp";
  std::string enc_path_ = "test_enc.tmp";
  std::string dec_path_ = "test_dec.tmp";

  /**
   * @brief   Clean up temporary files after each test
   */
  void TearDown() override {
    RemoveFile(src_path_);
    RemoveFile(enc_path_);
    RemoveFile(dec_path_);
  }

  /**
   * @brief   Create test file
   * @param   path    File path
   * @param   data    File content
   * @param   size    File size
   */
  void Create(const std::string& path, std::vector<uint8_t>& data, int size) {
    FILE* file = nullptr;

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
  void Read(std::string& path, std::vector<uint8_t>& vec) {
    FILE* file = nullptr;
    uint64_t size;

    OpenFile(&file, path, "rb");

    if (!file)
      return;

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
 * @brief   Verify encryption and decryption works with no error, and decrypted
 * data is identical to original
 */
TEST_F(TEST, EncryptDecryptBasic) {
  AesGcm aes;
  FILE *src = nullptr, *dst = nullptr;
  std::vector<uint8_t> orig, copy;
  const char* data = "Hello, world!";
  const char* pw = "password";
  int dsize = strlen(data);
  int psize = strlen(pw);
  int res;

  for (int i = 0; i < dsize; i++) {
    orig.push_back(data[i]);
  }

  Create(src_path_, orig, dsize);

  /* Encrypt */

  OpenFile(&src, src_path_, "rb");
  OpenFile(&dst, enc_path_, "wb+");

  res = aes.Encrypt(src, dst, pw, psize);

  if (src) {
    fclose(src);
  }

  if (dst) {
    fclose(dst);
  }

  EXPECT_EQ(res, 0);

  /* Decrypt */

  OpenFile(&src, enc_path_, "rb");
  OpenFile(&dst, dec_path_, "wb+");

  res = aes.Decrypt(src, dst, pw, psize);

  if (src) {
    fclose(src);
  }

  if (dst) {
    fclose(dst);
  }

  EXPECT_EQ(res, 0);

  /* Compare with original */

  Read(dec_path_, copy);

  EXPECT_EQ(orig, copy);
}

/* ==================================================
 * Authentication Tests
 * ================================================== */

/**
 * @brief   Verify decryption fails with wrong password
 */
TEST_F(TEST, WrongPasswordFails) {
  AesGcm aes;
  FILE *src = nullptr, *dst = nullptr;
  std::vector<uint8_t> orig;
  const char* data = "Hello, world!";
  const char *pw0 = "password", *pw1 = "asdf1234";
  int dsize = strlen(data);
  int psize0 = strlen(pw0), psize1 = strlen(pw1);
  int res;

  for (int i = 0; i < dsize; i++) {
    orig.push_back(data[i]);
  }

  Create(src_path_, orig, dsize);

  /* Encrypt */

  OpenFile(&src, src_path_, "rb");
  OpenFile(&dst, enc_path_, "wb+");

  aes.Encrypt(src, dst, pw0, psize0);

  if (src) {
    fclose(src);
  }

  if (dst) {
    fclose(dst);
  }

  /* Decrypt with wrong password */

  OpenFile(&src, enc_path_, "rb");
  OpenFile(&dst, dec_path_, "wb");

  res = aes.Decrypt(src, dst, pw1, psize1);

  if (src) {
    fclose(src);
  }

  if (dst) {
    fclose(dst);
  }

  EXPECT_NE(res, 0);
}

/**
 * @brief   Verify tampered ciphertext fails decryption
 */
TEST_F(TEST, TamperedCipherFails) {
  AesGcm aes;
  FILE *src = nullptr, *dst = nullptr;
  std::vector<uint8_t> orig, copy;
  const char* data = "Hello, world!";
  const char* pw = "password";
  int dsize = strlen(data);
  int psize = strlen(pw);
  int res;

  for (int i = 0; i < dsize; i++) {
    orig.push_back(data[i]);
  }

  Create(src_path_, orig, dsize);

  /* Encrypt */

  OpenFile(&src, src_path_, "rb");
  OpenFile(&dst, enc_path_, "wb+");

  aes.Encrypt(src, dst, pw, psize);

  if (src) {
    fclose(src);
  }

  if (dst) {
    fclose(dst);
  }

  /* Tamper ciphertext */

  Read(enc_path_, copy);

  copy[kSaltSize + kIVSize] ^= 0xFF;

  Create(enc_path_, copy, copy.size());

  /* Decrypt */

  OpenFile(&src, enc_path_, "rb");
  OpenFile(&dst, dec_path_, "wb+");

  res = aes.Decrypt(src, dst, pw, psize);

  if (src) {
    fclose(src);
  }

  if (dst) {
    fclose(dst);
  }

  EXPECT_NE(res, 0);
}

/* ==================================================
 * Edge Case Tests
 * ================================================== */

/**
 * @brief   Verify empty file can be encrypted and decrypted
 */
TEST_F(TEST, EmptyFile) {
  AesGcm aes;
  FILE *src = nullptr, *dst = nullptr;
  std::vector<uint8_t> orig, copy;
  const char* pw = "password";
  int dsize = 0;
  int psize = strlen(pw);
  int res;

  Create(src_path_, orig, dsize);

  /* Encrypt */

  OpenFile(&src, src_path_, "rb");
  OpenFile(&dst, enc_path_, "wb+");

  res = aes.Encrypt(src, dst, pw, psize);

  if (src) {
    fclose(src);
  }

  if (dst) {
    fclose(dst);
  }

  EXPECT_EQ(res, 0);

  /* Decrypt */

  OpenFile(&src, enc_path_, "rb");
  OpenFile(&dst, dec_path_, "wb+");

  res = aes.Decrypt(src, dst, pw, psize);

  if (src) {
    fclose(src);
  }

  if (dst) {
    fclose(dst);
  }

  EXPECT_EQ(res, 0);

  /* Compare with original */

  Read(dec_path_, copy);

  EXPECT_EQ(orig, copy);
}

/**
 * @brief   Verify file with exact buffer size works correctly
 */
TEST_F(TEST, ExactBuffSizeFile) {
  AesGcm aes;
  FILE *src = nullptr, *dst = nullptr;
  std::vector<uint8_t> orig, copy;
  const char* pw = "password";
  int dsize = kBlockSize * kBuffSize;
  int psize = strlen(pw);
  int res;

  orig.resize(dsize, 'a');

  Create(src_path_, orig, dsize);

  /* Encrypt */

  OpenFile(&src, src_path_, "rb");
  OpenFile(&dst, enc_path_, "wb+");

  res = aes.Encrypt(src, dst, pw, psize);

  if (src) {
    fclose(src);
  }

  if (dst) {
    fclose(dst);
  }

  EXPECT_EQ(res, 0);

  /* Decrypt */

  OpenFile(&src, enc_path_, "rb");
  OpenFile(&dst, dec_path_, "wb+");

  res = aes.Decrypt(src, dst, pw, psize);

  if (src) {
    fclose(src);
  }

  if (dst) {
    fclose(dst);
  }

  EXPECT_EQ(res, 0);

  /* Compare with original */

  Read(dec_path_, copy);

  EXPECT_EQ(orig, copy);
}

/**
 * @brief   Verify arbitrary sized file works correctly
 */
TEST_F(TEST, ArbitrarySizeFile) {
  AesGcm aes;
  FILE *src = nullptr, *dst = nullptr;
  std::vector<uint8_t> orig, copy;
  const char* pw = "password";
  int dsize = 50000;
  int psize = strlen(pw);
  int res;

  orig.resize(dsize, 'a');

  Create(src_path_, orig, dsize);

  /* Encrypt */

  OpenFile(&src, src_path_, "rb");
  OpenFile(&dst, enc_path_, "wb+");

  res = aes.Encrypt(src, dst, pw, psize);

  if (src) {
    fclose(src);
  }

  if (dst) {
    fclose(dst);
  }

  EXPECT_EQ(res, 0);

  /* Decrypt */

  OpenFile(&src, enc_path_, "rb");
  OpenFile(&dst, dec_path_, "wb+");

  res = aes.Decrypt(src, dst, pw, psize);

  if (src) {
    fclose(src);
  }

  if (dst) {
    fclose(dst);
  }

  EXPECT_EQ(res, 0);

  /* Compare with original */

  Read(dec_path_, copy);

  EXPECT_EQ(orig, copy);
}

/* ==================================================
 * Callback Tests
 * ================================================== */

/**
 * @brief   Verify progress callback is invoked during encryption
 */
TEST_F(TEST, ProgressCallback) {
  AesGcm aes;
  FILE *src = nullptr, *dst = nullptr;
  std::vector<uint8_t> orig;
  const char* pw = "password";
  int dsize = kBlockSize * kBuffSize * 10;
  int psize = strlen(pw);
  int cnt = 0, last = -1;

  orig.resize(dsize, 'a');

  Create(src_path_, orig, dsize);

  /* Encrypt with progress callback */

  OpenFile(&src, src_path_, "rb");
  OpenFile(&dst, enc_path_, "wb+");

  aes.SetProgressCallback([&](int perc, bool* cancelled) {
    cnt++;

    EXPECT_GE(perc, last);

    last = perc;
  });

  aes.Encrypt(src, dst, pw, psize);

  if (src) {
    fclose(src);
  }

  if (dst) {
    fclose(dst);
  }

  EXPECT_GT(cnt, 0);
}

/**
 * @brief   Verify error callback is invoked on failure
 */
TEST_F(TEST, ErrorCallback) {
  AesGcm aes;
  FILE *src = nullptr, *dst = nullptr;
  std::vector<uint8_t> orig;
  bool b = false;
  const char* data = "Hello, world!";
  const char *pw0 = "password", *pw1 = "asdf1234";
  int dsize = strlen(data);
  int psize0 = strlen(pw0), psize1 = strlen(pw1);

  for (int i = 0; i < dsize; i++)
    orig.push_back(data[i]);

  Create(src_path_, orig, dsize);

  /* Encrypt */

  OpenFile(&src, src_path_, "rb");
  OpenFile(&dst, enc_path_, "wb+");

  aes.Encrypt(src, dst, pw0, psize0);

  if (src) {
    fclose(src);
  }

  if (dst) {
    fclose(dst);
  }

  /* Decrypt with wrong password and error callback */

  OpenFile(&src, enc_path_, "rb");
  OpenFile(&dst, dec_path_, "wb+");

  aes.SetErrorCallback([&](const char* msg) { b = true; });

  aes.Decrypt(src, dst, pw1, psize1);

  if (src) {
    fclose(src);
  }

  if (dst) {
    fclose(dst);
  }

  EXPECT_TRUE(b);
}

/* ==================================================
 * Cancellation Tests
 * ================================================== */

/**
 * @brief   Verify cancellation works
 */
TEST_F(TEST, Cancellation) {
  AesGcm aes;
  FILE *src = nullptr, *dst = nullptr;
  std::vector<uint8_t> orig;
  const char* pw = "password";
  int dsize = kBlockSize * kBuffSize * 10;
  int psize = strlen(pw);
  int cnt = 0, res;

  orig.resize(dsize, 'a');

  Create(src_path_, orig, dsize);

  /* Encrypt and cancel after the second callback */

  OpenFile(&src, src_path_, "rb");
  OpenFile(&dst, enc_path_, "wb+");

  aes.SetProgressCallback([&](int perc, bool* cancelled) {
    cnt++;

    if (cnt >= 2) {
      *cancelled = true;
    }
  });

  res = aes.Encrypt(src, dst, pw, psize);

  if (src) {
    fclose(src);
  }

  if (dst) {
    fclose(dst);
  }

  EXPECT_NE(res, 0);
  EXPECT_GE(cnt, 2);
  EXPECT_LE(cnt, 3);
}