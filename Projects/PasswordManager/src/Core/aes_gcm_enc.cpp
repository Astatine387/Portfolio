/**
 * @file	aes_gcm_enc.cpp
 * @brief	Implementation of encryption functions of AesGcm class
 * @author	Astatine387
 */

#include <cstring>

#include "Core/aes_gcm.h"
#include "Utils/platform.h"

int AesGcm::Encrypt(uint8_t* src, uint8_t* dst, size_t size, const char* pw,
                    size_t plen) {
  src_buff_ = src;
  dst_buff_ = dst;
  size_ = size;
  src_crs_ = 0;
  dst_crs_ = 0;

  if (EncryptInit(pw, plen)) {
    return 1;  // LCOV_EXCL_LINE
  }

  if (EncryptBuff()) {
    return 1;  // LCOV_EXCL_LINE
  }

  if (EncryptFinal()) {
    return 1;  // LCOV_EXCL_LINE
  }

  if (EncryptTag()) {
    return 1;  // LCOV_EXCL_LINE
  }

  return 0;
}

int AesGcm::EncryptInit(const char* pw, size_t plen) {
  /* Clear existing context */

  if (ctx_) {
    EVP_CIPHER_CTX_free(ctx_);
    ctx_ = nullptr;
  }

  /* Generate salt and IV */

  if (Random(salt_, kSaltSize)) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Random failed - Cannot generate salt\n");
    return 1;
    // LCOV_EXCL_STOP
  }

  if (Random(iv_, kIVSize)) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Random failed - Cannot generate initial vector\n");
    return 1;
    // LCOV_EXCL_STOP
  }

  /* Derive key from password */

  if (Argon2id(salt_, pw, plen, key_)) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Key derivation failed - Argon2id error\n");
    return 1;
    // LCOV_EXCL_STOP
  }

  /* Set encryption context */

  if (!(ctx_ = EVP_CIPHER_CTX_new())) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Initialization failed - Cannot create context\n");
    return 1;
    // LCOV_EXCL_STOP
  }

  if (EVP_EncryptInit_ex(ctx_, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
    // LCOV_EXCL_START
    ReportError(
        "[Crypto] Initialization failed - Cannot set AES-256-GCM algorithm\n");
    return 1;
    // LCOV_EXCL_STOP
  }

  if (EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_GCM_SET_IVLEN, kIVSize, NULL) != 1) {
    // LCOV_EXCL_START
    ReportError(
        "[Crypto] Initialization failed - Cannot set initial vector size\n");
    return 1;
    // LCOV_EXCL_STOP
  }

  if (EVP_EncryptInit_ex(ctx_, NULL, NULL, key_, iv_) != 1) {
    // LCOV_EXCL_START
    ReportError(
        "[Crypto] Initialization failed - Cannot set key and initial vector\n");
    return 1;
    // LCOV_EXCL_STOP
  }

  /* Write salt and IV */

  memcpy(dst_buff_ + dst_crs_, salt_, kSaltSize);
  dst_crs_ += kSaltSize;

  memcpy(dst_buff_ + dst_crs_, iv_, kIVSize);
  dst_crs_ += kIVSize;

  return 0;
}

int AesGcm::EncryptBuff() {
  int out_len;

  if (EVP_EncryptUpdate(ctx_, dst_buff_ + dst_crs_, &out_len, src_buff_,
                        size_) != 1) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Encryption failed - Cannot encrypt buffer\n");
    return 1;
    // LCOV_EXCL_STOP
  }

  if (out_len != size_) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Encryption failed - Cannot encrypt buffer\n");
    return 1;
    // LCOV_EXCL_STOP
  }

  dst_crs_ += size_;

  return 0;
}

int AesGcm::EncryptFinal() {
  uint8_t final_buff[kBlockSize];
  int final_len;

  if (EVP_EncryptFinal_ex(ctx_, final_buff, &final_len) != 1) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Finalization failed - Cannot finalize encryption\n");
    return 1;
    // LCOV_EXCL_STOP
  }

  if (final_len > 0) {
    // LCOV_EXCL_START
    ReportError(
        "[Crypto] Finalization failed - Unexpected output from finalization\n");
    return 1;
    // LCOV_EXCL_STOP
  }

  memcpy(dst_buff_ + dst_crs_, final_buff, final_len);
  dst_crs_ += final_len;

  return 0;
}

int AesGcm::EncryptTag() {
  uint8_t tag[kTagSize];

  if (EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_GCM_GET_TAG, kTagSize, tag) != 1) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Tag Error - Cannot get authentication tag\n");
    return 1;
    // LCOV_EXCL_STOP
  }

  memcpy(dst_buff_ + dst_crs_, tag, kTagSize);
  dst_crs_ += kTagSize;

  return 0;
}