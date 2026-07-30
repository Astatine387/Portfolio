/**
 * @file	aes_gcm_enc.cpp
 * @brief	Implementation of encryption function of AES_GCM class
 * @author	Astatine387
 */

#include <array>

#include "core/aes_gcm.h"
#include "utils/platform.h"

Result AesGcm::Encrypt(FILE* src, FILE* dst, const SecureKey& key, std::span<const uint8_t, kSaltSize> salt) {
  src_file_ = src;
  dst_file_ = dst;
  progress_cur_ = 0;
  last_perc_ = -1;
  key_ = &key;

  /* Drain any write left over from a previous (possibly aborted) run, then arm a clean result */

  FlushWrite();

  {
    std::scoped_lock lk(write_mtx_);
    write_result_ = Result::kSuccess;
  }

  /* Drain the writer on every exit path so the caller can safely close the destination file */

  WriterGuard writer_guard(this);

  if (EncryptInit(salt) == Result::kFailure) {
    return Result::kFailure;  // LCOV_EXCL_LINE
  }

  if (EncryptBatch() == Result::kFailure) {
    return Result::kFailure;  // LCOV_EXCL_LINE
  }

  if (EncryptRemain() == Result::kFailure) {
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

  /* Get source file size */

  src_size_ = GetFileSize(src_file_);

  if (src_size_ == -1) {
    // LCOV_EXCL_START
    ReportError("[File] Size check failed - Cannot read source file size\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  if (src_size_ > kMaxSize) {
    // LCOV_EXCL_START
    ReportError("[File] Validation failed - File should be at most 64 GiB\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  progress_max_ = src_size_;

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

  /* Write the salt and the fresh IV to the header */

  if (fwrite(salt.data(), sizeof(uint8_t), kSaltSize, dst_file_) != kSaltSize) {
    // LCOV_EXCL_START
    ReportError("[File] Write failed - Cannot write salt to destination file header\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  if (fwrite(iv_.data(), sizeof(uint8_t), kIVSize, dst_file_) != kIVSize) {
    // LCOV_EXCL_START
    ReportError("[File] Write failed - Cannot write IV to destination file header\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  return Result::kSuccess;
}

Result AesGcm::EncryptBuff(void* src, void* dst, int srclen) {
  int dstlen;

  if (EVP_EncryptUpdate(ctx_, static_cast<unsigned char*>(dst), &dstlen, static_cast<unsigned char*>(src), srclen) !=
      1) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Encryption failed - Cannot encrypt buffer\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  if (dstlen != srclen) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Encryption failed - Cannot encrypt buffer\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  return Result::kSuccess;
}

Result AesGcm::EncryptBatch() {
  int cur = 0;

  while (progress_cur_ + static_cast<int64_t>(kBuffSize * kBlockSize) <= src_size_) {
    /* Read and encrypt current buffer */

    if (ReadFile(buff_[cur].data(), kBuffSize * kBlockSize) == Result::kFailure) {
      return Result::kFailure;  // LCOV_EXCL_LINE
    }

    if (EncryptBuff(buff_[cur].data(), buff_[cur].data(), kBuffSize * kBlockSize) == Result::kFailure) {
      return Result::kFailure;  // LCOV_EXCL_LINE
    }

    /* Queue the buffer for asynchronous writing (waits for the previous write to finish) */

    if (SubmitWrite(buff_[cur].data(), kBuffSize * kBlockSize) == Result::kFailure) {
      return Result::kFailure;  // LCOV_EXCL_LINE
    }

    /* Swap buffer */

    cur = 1 - cur;

    /* Update progress */

    progress_cur_ += kBuffSize * kBlockSize;

    ReportProgress();

    if (IsCancelled()) {
      FlushWrite();
      return Result::kFailure;
    }
  }

  /* Wait for the last write to finish */

  if (FlushWrite() == Result::kFailure) {
    return Result::kFailure;  // LCOV_EXCL_LINE
  }

  return Result::kSuccess;
}

Result AesGcm::EncryptRemain() {
  int rem = static_cast<int>(src_size_ % (kBuffSize * kBlockSize));

  if (ReadFile(buff_[0].data(), rem) == Result::kFailure) {
    return Result::kFailure;  // LCOV_EXCL_LINE
  }

  /* Encrypt all remaining data at once */

  if (EncryptBuff(buff_[0].data(), buff_[0].data(), rem) == Result::kFailure) {
    return Result::kFailure;  // LCOV_EXCL_LINE
  }

  if (WriteFile(buff_[0].data(), rem) == Result::kFailure) {
    return Result::kFailure;  // LCOV_EXCL_LINE
  }

  progress_cur_ += rem;

  ReportProgress();

  if (IsCancelled()) {
    return Result::kFailure;  // LCOV_EXCL_LINE
  }

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

  if (final_len > 0 && WriteFile(final_block.data(), final_len) == Result::kFailure) {
    return Result::kFailure;  // LCOV_EXCL_LINE
  }

  return Result::kSuccess;
}

Result AesGcm::EncryptTag() {
  std::array<uint8_t, kTagSize> tag{};

  if (EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_GCM_GET_TAG, kTagSize, tag.data()) != 1) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Tag Error - Cannot get auth tag\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  if (fwrite(tag.data(), sizeof(uint8_t), kTagSize, dst_file_) != kTagSize) {
    // LCOV_EXCL_START
    ReportError("[File] Write failed - Cannot write auth tag on destination file\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  return Result::kSuccess;
}