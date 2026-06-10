/**
 * @file	aes_gcm_dec.cpp
 * @brief	Implementation of decryption function of AES_GCM class
 * @author	Astatine387
 */

#include <algorithm>

#include "core/aes_gcm.h"
#include "utils/platform.h"

Result AesGcm::Decrypt(FILE* src, FILE* dst, const char* pw, size_t plen) {
  src_file_ = src;
  dst_file_ = dst;
  cancelled_ = false;
  progress_cur_ = 0;
  writing_ = false;

  if (DecryptInit(pw, plen) == Result::kFailure) {
    return Result::kFailure;  // LCOV_EXCL_LINE
  }

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

Result AesGcm::DecryptInit(const char* pw, size_t plen) {
  /* Abort if the key buffer is not locked in memory */

  if (!key_locked_) {
    // LCOV_EXCL_START
    ReportError("[Memory] Lock failed - Cannot lock key in memory\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  /* Get source file size */

  src_size_ = GetFileSize(src_file_);

  if (src_size_ == -1) {
    // LCOV_EXCL_START
    ReportError("[File] Size check failed - Cannot read source file size\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  if (src_size_ < kSaltSize + kIVSize + kTagSize) {
    // LCOV_EXCL_START
    ReportError("[File] Validation failed - File should be at least 44 bytes\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  src_size_ -= kSaltSize + kIVSize + kTagSize;

  /* Double the progress as there are two passes */

  progress_max_ = 2 * src_size_;

  /* Read salt and IV from header */

  if (fread(salt_.data(), sizeof(uint8_t), kSaltSize, src_file_) != kSaltSize) {
    // LCOV_EXCL_START
    ReportError("[File] Read failed - Cannot read salt from source file header\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  if (fread(iv_.data(), sizeof(uint8_t), kIVSize, src_file_) != kIVSize) {
    // LCOV_EXCL_START
    ReportError(
        "[File] Read failed - Cannot read initial vector from source file "
        "header\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  /* Read authentication tag from the end of the file */

  if (Seek(src_file_, -static_cast<int64_t>(kTagSize), SEEK_END) == Result::kFailure) {
    // LCOV_EXCL_START
    ReportError("[File] Seek failed - Cannot move file pointer to authentication tag\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  if (fread(tag_.data(), sizeof(uint8_t), kTagSize, src_file_) != kTagSize) {
    // LCOV_EXCL_START
    ReportError("[File] Read failed - Cannot read authentication tag\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  /* Derive key from password */

  if (Argon2id(salt_.data(), pw, plen, key_.data()) == Result::kFailure) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Key derivation failed - Argon2id error\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  return Result::kSuccess;
}

Result AesGcm::DecryptBuff(void* src, void* dst, int srclen) {
  int dstlen;

  if (EVP_DecryptUpdate(ctx_, static_cast<unsigned char*>(dst), &dstlen, static_cast<unsigned char*>(src), srclen) !=
      1) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Decryption failed - Cannot decrypt buffer\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  if (dstlen != srclen) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Decryption failed - Cannot decrypt buffer\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  return Result::kSuccess;
}

Result AesGcm::DecryptBatch(DecryptMode mode) {
  if (SetupDecryptCtx() == Result::kFailure) {
    return Result::kFailure;  // LCOV_EXCL_LINE
  }

  int64_t rem = src_size_;

  while (rem > 0) {
    int chunk = static_cast<int>(std::min<int64_t>(rem, kBuffSize * kBlockSize));

    if (ReadFile(buff_[0].data(), chunk) == Result::kFailure) {
      return Result::kFailure;  // LCOV_EXCL_LINE
    }

    if (DecryptBuff(buff_[0].data(), buff_[0].data(), chunk) == Result::kFailure) {
      return Result::kFailure;  // LCOV_EXCL_LINE
    }

    if (mode == DecryptMode::kWrite && WriteFile(buff_[0].data(), chunk) == Result::kFailure) {
      return Result::kFailure;  // LCOV_EXCL_LINE
    }

    rem -= chunk;
    progress_cur_ += chunk;

    if (ReportProgress() == Progress::kCancelled) {
      return Result::kFailure;
    }
  }

  if (DecryptFinal() == Result::kFailure) {
    return Result::kFailure;
  }

  return Result::kSuccess;
}

Result AesGcm::DecryptFinal() {
  std::array<uint8_t, kBlockSize> final_block{};
  int final_len;

  if (EVP_DecryptFinal_ex(ctx_, final_block.data(), &final_len) != 1) {
    ReportError("[Auth] Verification failed - Invalid password or corrupted file\n");
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

  if (EVP_DecryptInit_ex(ctx_, nullptr, nullptr, key_.data(), iv_.data()) != 1) {
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

  /* Move file pointer to the start of the ciphertext */

  if (Seek(src_file_, kSaltSize + kIVSize, SEEK_SET) == Result::kFailure) {
    // LCOV_EXCL_START
    ReportError("[File] Seek failed - Cannot move file pointer to data\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  return Result::kSuccess;
}