/**
 * @file	aes_gcm_enc.cpp
 * @brief	Implementation of encryption functions of AesGcm class
 * @author	Astatine387
 */

#include <cstring>
#include <utility>

#include "core/aes_gcm.h"
#include "utils/platform.h"

Result AesGcm::Encrypt(uint8_t* src, uint8_t* dst, size_t size, const SecureKey& key,
                       std::span<const uint8_t, kSaltSize> salt) {
  src_buff_ = src;
  dst_buff_ = dst;
  size_ = size;
  dst_crs_ = 0;
  key_ = &key;

  if (EncryptInit(salt) == Result::kFailure) {
    return Result::kFailure;  // LCOV_EXCL_LINE
  }

  if (EncryptBuff() == Result::kFailure) {
    return Result::kFailure;  // LCOV_EXCL_LINE
  }

  if (EncryptFinal() == Result::kFailure) {
    return Result::kFailure;  // LCOV_EXCL_LINE
  }

  if (EncryptTag() == Result::kFailure) {
    return Result::kFailure;  // LCOV_EXCL_LINE
  }

  return Result::kSuccess;
}

Result AesGcm::EncryptInit(std::span<const uint8_t, kSaltSize> salt) {
  /* Clear existing context */

  if (ctx_) {
    EVP_CIPHER_CTX_free(ctx_);
    ctx_ = nullptr;
  }

  /* Generate a new IV for every encryption */

  if (Random(iv_.data(), kIVSize) == Result::kFailure) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Random failed - Cannot generate initial vector\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  /* Set encryption context */

  ctx_ = EVP_CIPHER_CTX_new();

  if (!ctx_) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Initialization failed - Cannot create context\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  if (EVP_EncryptInit_ex(ctx_, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Initialization failed - Cannot set AES-256-GCM algorithm\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  if (EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_GCM_SET_IVLEN, kIVSize, nullptr) != 1) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Initialization failed - Cannot set initial vector size\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  if (EVP_EncryptInit_ex(ctx_, nullptr, nullptr, key_->Bytes().data(), iv_.data()) != 1) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Initialization failed - Cannot set key and initial vector\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  /* Write the session salt and the fresh IV to the header */

  memcpy(dst_buff_ + dst_crs_, salt.data(), kSaltSize);
  dst_crs_ += kSaltSize;

  memcpy(dst_buff_ + dst_crs_, iv_.data(), kIVSize);
  dst_crs_ += kIVSize;

  return Result::kSuccess;
}

Result AesGcm::EncryptBuff() {
  int out_len;

  if (EVP_EncryptUpdate(ctx_, dst_buff_ + dst_crs_, &out_len, src_buff_, static_cast<int>(size_)) != 1) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Encryption failed - Cannot encrypt buffer\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  if (std::cmp_not_equal(out_len, size_)) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Encryption failed - Cannot encrypt buffer\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  dst_crs_ += size_;

  return Result::kSuccess;
}

Result AesGcm::EncryptFinal() {
  std::array<uint8_t, kBlockSize> final_block{};
  int final_len;

  if (EVP_EncryptFinal_ex(ctx_, final_block.data(), &final_len) != 1) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Finalization failed - Cannot finalize encryption\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  if (final_len > 0) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Finalization failed - Unexpected output from finalization\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  memcpy(dst_buff_ + dst_crs_, final_block.data(), final_len);
  dst_crs_ += final_len;

  return Result::kSuccess;
}

Result AesGcm::EncryptTag() {
  std::array<uint8_t, kTagSize> tag{};

  if (EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_GCM_GET_TAG, kTagSize, tag.data()) != 1) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Tag Error - Cannot get authentication tag\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  memcpy(dst_buff_ + dst_crs_, tag.data(), kTagSize);
  dst_crs_ += kTagSize;

  return Result::kSuccess;
}