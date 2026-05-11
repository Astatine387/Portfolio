/**
 * @file	AES_GCM_dec.cpp
 * @brief	Implementation of decryption functions AES_GCM class
 * @author	Astatine387
 */

#include "Core/AES_GCM.h"
#include "Utils/library.h"

#include <cstring>

int AES_GCM::Decrypt(uint8_t* src, uint8_t* dst, size_t size, const char* pw, size_t plen) {
  src_buff_ = src;
  dst_buff_ = dst;
  size_ = size;
  src_crs_ = 0;
  dst_crs_ = 0;

  if (DecryptInit(pw, plen)) {
    return 1;  // LCOV_EXCL_LINE
  }

  if (DecryptTag()) {
    return 1;  // LCOV_EXCL_LINE
  }

  if (DecryptBuff()) {
    return 1;  // LCOV_EXCL_LINE
  }

  if (DecryptFinal()) {
    return 1;  // LCOV_EXCL_LINE
  }

  return 0;
}

int AES_GCM::DecryptInit(const char* pw, size_t plen) {
  /* Clear existing context */

  if (ctx_) {
    EVP_CIPHER_CTX_free(ctx_);
    ctx_ = nullptr;
  }

  /* Read salt and IV */

  memcpy(salt_, src_buff_ + src_crs_, kSaltSize);
  src_crs_ += kSaltSize;

  memcpy(iv_, src_buff_ + src_crs_, kIVSize);
  src_crs_ += kIVSize;

  /* Derive key from password */

  if (Argon2id(salt_, pw, plen, key_)) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Key derivation failed - Argon2id error\n");
    return 1;
    // LCOV_EXCL_STOP
  }

  /* Set decryption context */

  if (!(ctx_ = EVP_CIPHER_CTX_new())) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Initialization failed - Cannot create context\n");
    return 1;
    // LCOV_EXCL_STOP
  }

  if (EVP_DecryptInit_ex(ctx_, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Initialization failed - Cannot set AES-256-GCM algorithm\n");
    return 1;
    // LCOV_EXCL_STOP
  }

  if (EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_GCM_SET_IVLEN, kIVSize, NULL) != 1) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Initialization failed - Cannot set initial vector size\n");
    return 1;
    // LCOV_EXCL_STOP
  }

  if (EVP_DecryptInit_ex(ctx_, NULL, NULL, key_, iv_) != 1) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Initialization failed - Cannot set key and initial vector\n");
    return 1;
    // LCOV_EXCL_STOP
  }

  return 0;
}

int AES_GCM::DecryptTag() {
  uint8_t tag[kTagSize];

  memcpy(tag, src_buff_ + size_ - kTagSize, kTagSize);

  if (EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_GCM_SET_TAG, kTagSize, tag) != 1) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Tag failed - Cannot set authentication tag\n");
    return 1;
    // LCOV_EXCL_STOP
  }

  return 0;
}

int AES_GCM::DecryptBuff() {
  int in_len = size_ - kSaltSize - kIVSize - kTagSize;
  int out_len;

  if (EVP_DecryptUpdate(ctx_, dst_buff_, &out_len, src_buff_ + src_crs_, in_len) != 1) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Decryption failed - Cannot decrypt buffer\n");
    return 1;
    // LCOV_EXCL_STOP
  }

  if (out_len != in_len) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Decryption failed - Cannot decrypt buffer\n");
    return 1;
    // LCOV_EXCL_STOP
  }

  dst_crs_ += in_len;

  return 0;
}

int AES_GCM::DecryptFinal() {
  uint8_t final_buff[kBlockSize];
  int final_len;

  if (EVP_DecryptFinal_ex(ctx_, final_buff, &final_len) != 1) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Finalization failed - Cannot finalize decryption\n");
    return 1;
    // LCOV_EXCL_STOP
  }

  if (final_len > 0) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Finalization failed - Unexpected output from finalization\n");
    return 1;
    // LCOV_EXCL_STOP
  }

  memcpy(dst_buff_ + dst_crs_, final_buff, final_len);
  dst_crs_ += final_len;

  return 0;
}