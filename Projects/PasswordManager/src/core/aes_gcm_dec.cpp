/**
 * @file	aes_gcm_dec.cpp
 * @brief	Implementation of decryption functions of AesGcm class
 * @author	Astatine387
 */

#include <algorithm>
#include <cstring>

#include "core/aes_gcm.h"

Result AesGcm::Decrypt(uint8_t* src, uint8_t* dst, size_t size, const SecureKey& key) {
  src_buff_ = src;
  dst_buff_ = dst;
  size_ = size;
  dst_crs_ = 0;
  key_ = &key;

  DecryptInit();

  /* Pass 1 - verify authentication tag */

  if (DecryptBatch(DecryptMode::kVerify) == Result::kFailure) {
    return Result::kFailure;
  }

  /* Pass 2 - write plaintext */

  if (DecryptBatch(DecryptMode::kWrite) == Result::kFailure) {
    return Result::kFailure;  // LCOV_EXCL_LINE
  }

  return Result::kSuccess;
}

void AesGcm::DecryptInit() {
  /* Read the IV from the header */

  memcpy(iv_.data(), src_buff_ + kSaltSize, kIVSize);
  memcpy(tag_.data(), src_buff_ + size_ - kTagSize, kTagSize);
}

Result AesGcm::DecryptBatch(DecryptMode mode) {
  if (SetupDecryptCtx() == Result::kFailure) {
    return Result::kFailure;  // LCOV_EXCL_LINE
  }

  int64_t rem = static_cast<int64_t>(size_ - kSaltSize - kIVSize - kTagSize);
  size_t src_crs = kSaltSize + kIVSize;
  size_t dst_crs = 0;

  while (rem > 0) {
    int chunk = static_cast<int>(std::min<int64_t>(rem, kBuffSize * kBlockSize));

    /* Decrypt into a temporary buffer */

    uint8_t* dst = (mode == DecryptMode::kWrite) ? dst_buff_ + dst_crs : verify_buff_.data();

    if (DecryptBuff(src_buff_ + src_crs, dst, chunk) == Result::kFailure) {
      return Result::kFailure;  // LCOV_EXCL_LINE
    }

    src_crs += chunk;
    dst_crs += chunk;
    rem -= chunk;
  }

  if (DecryptFinal() == Result::kFailure) {
    return Result::kFailure;
  }

  return Result::kSuccess;
}

Result AesGcm::SetupDecryptCtx() {
  /* Clear existing context */

  if (ctx_) {
    EVP_CIPHER_CTX_free(ctx_);
    ctx_ = nullptr;
  }

  ctx_ = EVP_CIPHER_CTX_new();

  if (!ctx_) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Initialization failed - Cannot create context\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  if (EVP_DecryptInit_ex(ctx_, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
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

  if (EVP_DecryptInit_ex(ctx_, nullptr, nullptr, key_->Bytes().data(), iv_.data()) != 1) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Initialization failed - Cannot set key and initial vector\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  if (EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_GCM_SET_TAG, kTagSize, tag_.data()) != 1) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Tag failed - Cannot set authentication tag\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  return Result::kSuccess;
}

Result AesGcm::DecryptBuff(const uint8_t* src, uint8_t* dst, int len) {
  int out_len;

  if (EVP_DecryptUpdate(ctx_, dst, &out_len, src, len) != 1) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Decryption failed - Cannot decrypt buffer\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  if (out_len != len) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Decryption failed - Cannot decrypt buffer\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  return Result::kSuccess;
}

Result AesGcm::DecryptFinal() {
  std::array<uint8_t, kBlockSize> final_block{};
  int final_len;

  if (EVP_DecryptFinal_ex(ctx_, final_block.data(), &final_len) != 1) {
    ReportError("[Auth] Verification failed - Invalid password or corrupted vault\n");
    return Result::kFailure;
  }

  return Result::kSuccess;
}
