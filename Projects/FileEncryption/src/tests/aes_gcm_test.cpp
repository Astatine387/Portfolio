/**
 * @file    aes_gcm_test.cpp
 * @brief   Unit tests for AES-GCM class
 * @author  Astatine387
 */

#include "core/aes_gcm.h"

#include <gtest/gtest.h>
#include <openssl/err.h>

#include <string>

#include "utils/platform.h"

/**
 * @class   AesGcmTest
 * @brief   Test fixture for AesGcm encryption/decryption tests
 */
class AesGcmTest : public ::testing::Test {
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
      if (size > 0) {
        fwrite(data.data(), sizeof(uint8_t), size, file);
      }

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
TEST_F(AesGcmTest, EncryptDecryptBasic) {
  AesGcm aes;
  FILE *src = nullptr, *dst = nullptr;
  const char* data = "Hello, world!";
  const char* pw = "password";
  int dsize = static_cast<int>(strlen(data));
  int psize = static_cast<int>(strlen(pw));
  Result res;
  std::vector<uint8_t> orig(data, data + dsize), copy;

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

  EXPECT_EQ(res, Result::kSuccess);

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

  EXPECT_EQ(res, Result::kSuccess);

  /* Compare with original */

  Read(dec_path_, copy);

  EXPECT_EQ(orig, copy);
}

/**
 * @brief   Verify a reused AesGcm frees its previous context before re-init
 */
TEST_F(AesGcmTest, ReuseFreesPreviousContext) {
  AesGcm aes;
  FILE *src = nullptr, *dst = nullptr;
  const char* data = "Hello, world!";
  const char* pw = "password";
  int dsize = static_cast<int>(strlen(data));
  int psize = static_cast<int>(strlen(pw));
  std::vector<uint8_t> orig(data, data + dsize);
  Result res0, res1;

  Create(src_path_, orig, dsize);

  /* First encryption - leaves a live context on the object */

  OpenFile(&src, src_path_, "rb");
  OpenFile(&dst, enc_path_, "wb+");

  res0 = aes.Encrypt(src, dst, pw, psize);

  if (src) {
    fclose(src);
  }

  if (dst) {
    fclose(dst);
  }

  /* Second encryption - EncryptInit must free the previous context */

  OpenFile(&src, src_path_, "rb");
  OpenFile(&dst, dec_path_, "wb+");

  res1 = aes.Encrypt(src, dst, pw, psize);

  if (src) {
    fclose(src);
  }

  if (dst) {
    fclose(dst);
  }

  EXPECT_EQ(res0, Result::kSuccess);
  EXPECT_EQ(res1, Result::kSuccess);
}

/* ==================================================
 * Authentication Tests
 * ================================================== */

/**
 * @brief   Verify decryption fails with wrong password
 */
TEST_F(AesGcmTest, WrongPasswordFails) {
  AesGcm aes;
  FILE *src = nullptr, *dst = nullptr;
  const char* data = "Hello, world!";
  const char *pw0 = "password", *pw1 = "asdf1234";
  int dsize = static_cast<int>(strlen(data));
  int psize0 = static_cast<int>(strlen(pw0));
  int psize1 = static_cast<int>(strlen(pw1));
  Result res;
  std::vector<uint8_t> orig(data, data + dsize);

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

  EXPECT_EQ(res, Result::kFailure);
}

/**
 * @brief   Verify tampered ciphertext fails decryption
 */
TEST_F(AesGcmTest, TamperedCipherFails) {
  AesGcm aes;
  FILE *src = nullptr, *dst = nullptr;
  const char* data = "Hello, world!";
  const char* pw = "password";
  int dsize = static_cast<int>(strlen(data));
  int psize = static_cast<int>(strlen(pw));
  Result res;
  std::vector<uint8_t> orig(data, data + dsize), copy;

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

  Create(enc_path_, copy, static_cast<int>(copy.size()));

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

  EXPECT_EQ(res, Result::kFailure);
}

/* ==================================================
 * Edge Case Tests
 * ================================================== */

/**
 * @brief   Verify empty file can be encrypted and decrypted
 */
TEST_F(AesGcmTest, EmptyFile) {
  AesGcm aes;
  FILE *src = nullptr, *dst = nullptr;
  std::vector<uint8_t> orig, copy;
  const char* pw = "password";
  int dsize = 0;
  int psize = static_cast<int>(strlen(pw));
  Result res;

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

  EXPECT_EQ(res, Result::kSuccess);

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

  EXPECT_EQ(res, Result::kSuccess);

  /* Compare with original */

  Read(dec_path_, copy);

  EXPECT_EQ(orig, copy);
}

/**
 * @brief   Verify file with exact buffer size works correctly
 */
TEST_F(AesGcmTest, ExactBuffSizeFile) {
  AesGcm aes;
  FILE *src = nullptr, *dst = nullptr;
  std::vector<uint8_t> orig, copy;
  const char* pw = "password";
  int dsize = kBlockSize * kBuffSize;
  int psize = static_cast<int>(strlen(pw));
  Result res;

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

  EXPECT_EQ(res, Result::kSuccess);

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

  EXPECT_EQ(res, Result::kSuccess);

  /* Compare with original */

  Read(dec_path_, copy);

  EXPECT_EQ(orig, copy);
}

/**
 * @brief   Verify arbitrary sized file works correctly
 */
TEST_F(AesGcmTest, ArbitrarySizeFile) {
  AesGcm aes;
  FILE *src = nullptr, *dst = nullptr;
  std::vector<uint8_t> orig, copy;
  const char* pw = "password";
  int dsize = 50000;
  int psize = static_cast<int>(strlen(pw));
  Result res;

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

  EXPECT_EQ(res, Result::kSuccess);

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

  EXPECT_EQ(res, Result::kSuccess);

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
TEST_F(AesGcmTest, ProgressCallback) {
  AesGcm aes;
  FILE *src = nullptr, *dst = nullptr;
  std::vector<uint8_t> orig;
  const char* pw = "password";
  int dsize = kBlockSize * kBuffSize * 10;
  int psize = static_cast<int>(strlen(pw));
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
TEST_F(AesGcmTest, ErrorCallback) {
  AesGcm aes;
  FILE *src = nullptr, *dst = nullptr;
  bool b = false;
  const char* data = "Hello, world!";
  const char *pw0 = "password", *pw1 = "asdf1234";
  int dsize = static_cast<int>(strlen(data));
  int psize0 = static_cast<int>(strlen(pw0));
  int psize1 = static_cast<int>(strlen(pw1));
  std::vector<uint8_t> orig(data, data + dsize);

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

/**
 * @brief   Verify ReportError formats and appends queued OpenSSL errors
 */
TEST_F(AesGcmTest, ErrorCallbackFormatsQueue) {
  AesGcm aes;
  FILE *src = nullptr, *dst = nullptr;
  bool called = false;
  std::string captured;
  const char* data = "Hello, world!";
  const char *pw0 = "password", *pw1 = "asdf1234";
  int dsize = static_cast<int>(strlen(data));
  int psize0 = static_cast<int>(strlen(pw0));
  int psize1 = static_cast<int>(strlen(pw1));
  std::vector<uint8_t> orig(data, data + dsize);

  Create(src_path_, orig, dsize);

  /* Encrypt with the correct password */

  OpenFile(&src, src_path_, "rb");
  OpenFile(&dst, enc_path_, "wb+");

  aes.Encrypt(src, dst, pw0, psize0);

  if (src) {
    fclose(src);
  }

  if (dst) {
    fclose(dst);
  }

  /* Seed the OpenSSL error queue, then fail decryption with a wrong password */

  OpenFile(&src, enc_path_, "rb");
  OpenFile(&dst, dec_path_, "wb+");

  aes.SetErrorCallback([&](const char* msg) {
    called = true;
    captured = msg;
  });

  ERR_clear_error();
  ERR_raise(ERR_LIB_USER, ERR_R_INTERNAL_ERROR);

  aes.Decrypt(src, dst, pw1, psize1);

  if (src) {
    fclose(src);
  }

  if (dst) {
    fclose(dst);
  }

  EXPECT_TRUE(called);
  EXPECT_NE(captured.find(" -> "), std::string::npos);
}

/* ==================================================
 * Cancellation Tests
 * ================================================== */

/**
 * @brief   Verify cancellation works
 */
TEST_F(AesGcmTest, Cancellation) {
  AesGcm aes;
  FILE *src = nullptr, *dst = nullptr;
  std::vector<uint8_t> orig;
  const char* pw = "password";
  int dsize = kBlockSize * kBuffSize * 10;
  int psize = static_cast<int>(strlen(pw));
  int cnt = 0;
  Result res;

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

  EXPECT_EQ(res, Result::kFailure);
  EXPECT_GE(cnt, 2);
  EXPECT_LE(cnt, 3);
}

/**
 * @brief   Verify cancelling during the decryption write pass waits for the ongoing async write before reporting
 * failure
 */
TEST_F(AesGcmTest, CancelDuringWritePass) {
  AesGcm aes;
  FILE *src = nullptr, *dst = nullptr;
  std::vector<uint8_t> orig;
  const char* pw = "password";
  int dsize = kBlockSize * kBuffSize * 10;
  int psize = static_cast<int>(strlen(pw));
  Result res;

  orig.resize(dsize, 'a');

  Create(src_path_, orig, dsize);

  /* Encrypt first to produce a valid ciphertext */

  OpenFile(&src, src_path_, "rb");
  OpenFile(&dst, enc_path_, "wb+");

  aes.Encrypt(src, dst, pw, psize);

  if (src) {
    fclose(src);
  }

  if (dst) {
    fclose(dst);
  }

  /* Decrypt, cancelling once the write pass is in progress (perc > 50) */

  OpenFile(&src, enc_path_, "rb");
  OpenFile(&dst, dec_path_, "wb+");

  aes.SetProgressCallback([&](int perc, bool* cancelled) {
    if (perc > 50) {
      *cancelled = true;
    }
  });

  res = aes.Decrypt(src, dst, pw, psize);

  if (src) {
    fclose(src);
  }

  if (dst) {
    fclose(dst);
  }

  EXPECT_EQ(res, Result::kFailure);
}