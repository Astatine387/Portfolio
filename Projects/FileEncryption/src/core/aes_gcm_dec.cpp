/**
 * @file    aes_gcm_dec.cpp
 * @brief   Implementation of decryption function of AES_GCM class
 * @author  Astatine387
 */

#include <array>
#include <limits>
#include <utility>

#include "core/aes_gcm.h"
#include "utils/platform.h"

Result AesGcm::Decrypt(FILE* src, FILE* dst, const SecureKey& key,
                       const FileHeader& header) {
  src_file_ = src;
  dst_file_ = dst;
  progress_cur_ = 0;
  last_perc_ = -1;
  key_ = &key;

  /* Wait until the ongoing write from a previous run finishes */

  FlushWrite();

  {
    UniqueLock lk(write_mtx_);
    write_result_ = Result::kSuccess;
  }

  /* Drain any ongoing asynchronous write when the scope exits */

  WriterGuard writer_guard(this);

  /* Check the header, prepare the context and buffers */

  if (DecryptInit(header) == Result::kFailure) {
    return Result::kFailure;
  }

  /* Decrypt and write the file */

  if (DecryptLoop() == Result::kFailure) {
    return Result::kFailure;
  }

  return Result::kSuccess;
}

Result AesGcm::DecryptInit(const FileHeader& header) {
  /* Check file size */

  src_size_ = GetFileSize(src_file_);

  if (src_size_ == -1) {
    // LCOV_EXCL_START
    ReportError("[File] Size check failed - Cannot read source file size\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  if (std::cmp_less(src_size_, kMinSize)) {
    ReportError(
        "[File] Validation failed - File is too small to be an encrypted "
        "file\n");
    return Result::kFailure;
  }

  /* Read and validate file header */

  const HeaderStatus status = ValidateHeader(header);

  if (status != HeaderStatus::kOk) {
    ReportError(HeaderErrorMessage(status));
    return Result::kFailure;
  }

  if (!key_->CommitmentMatches(header.commitment)) {
    ReportError(
        "[Auth] Verification failed - Wrong password, or the file header has "
        "been modified\n");
    return Result::kFailure;
  }

  chunk_size_ = size_t{ 1 } << header.chunk_log2;

  SerializeHeader(header_, header);

  src_size_ -= static_cast<int64_t>(kHeaderSize);

  progress_max_ = src_size_;

  AllocBuffers();

  /* Create a context and set the session key */

  if (SetupCtx(CryptoMode::kDecrypt) == Result::kFailure) {
    return Result::kFailure;  // LCOV_EXCL_LINE
  }

  /* Write the header */

  if (Seek(src_file_, static_cast<int64_t>(kHeaderSize), SEEK_SET) ==
      Result::kFailure) {
    // LCOV_EXCL_START
    ReportError("[File] Seek failed - Cannot move file pointer to data\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  return Result::kSuccess;
}

Result AesGcm::DecryptLoop() {
  int64_t rem = src_size_;
  uint64_t idx = 0;
  size_t cur = 0;

  while (rem > 0) {
    if (std::cmp_less(rem, kTagSize)) {
      ReportError(
          "[File] Validation failed - Encrypted file is truncated or "
          "corrupted\n");
      return Result::kFailure;
    }

    const bool is_last = std::cmp_less_equal(rem, chunk_size_ + kTagSize);
    const size_t len =
        is_last ? static_cast<size_t>(rem) - kTagSize : chunk_size_;

    if (ReadFile(buff_[cur].data(), len + kTagSize) == Result::kFailure) {
      return Result::kFailure;  // LCOV_EXCL_LINE
    }

    if (DecryptChunk(buff_[cur].data(), len, idx, is_last) ==
        Result::kFailure) {
      return Result::kFailure;
    }

    if (SubmitWrite(buff_[cur].data(), len) == Result::kFailure) {
      return Result::kFailure;
    }

    cur = 1 - cur;

    rem -= static_cast<int64_t>(len + kTagSize);
    progress_cur_ += static_cast<int64_t>(len + kTagSize);

    ReportProgress();

    if (IsCancelled()) {
      FlushWrite();
      return Result::kFailure;
    }

    if (idx == std::numeric_limits<uint64_t>::max()) {
      // LCOV_EXCL_START
      ReportError("[Crypto] Decryption failed - Chunk counter overflow\n");
      return Result::kFailure;
      // LCOV_EXCL_STOP
    }

    idx++;
  }

  /* Wait for the ongoing write to finish */

  if (FlushWrite() == Result::kFailure) {
    return Result::kFailure;
  }

  return Result::kSuccess;
}

Result AesGcm::DecryptChunk(uint8_t* buff, size_t len, uint64_t idx,
                            bool is_last) {
  BuildNonce(idx, is_last);

  if (EVP_DecryptInit_ex(ctx_, nullptr, nullptr, nullptr, nonce_.data()) != 1) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Decryption failed - Cannot set chunk nonce\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  int outlen = 0;

  if (EVP_DecryptUpdate(ctx_, nullptr, &outlen, header_.data(),
                        static_cast<int>(header_.size())) != 1) {
    // LCOV_EXCL_START
    ReportError(
        "[Crypto] Decryption failed - Cannot authenticate the header\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  if (EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_GCM_SET_TAG,
                          static_cast<int>(kTagSize), buff + len) != 1) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Tag failed - Cannot set authentication tag\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  if (len > 0) {
    /* Same buffer in and out: the plaintext overwrites the ciphertext it came
     * from, so a chunk needs no second buffer. It is still unverified at this
     * point. */

    if (EVP_DecryptUpdate(ctx_, buff, &outlen, buff, static_cast<int>(len)) !=
        1) {
      // LCOV_EXCL_START
      ReportError("[Crypto] Decryption failed - Cannot decrypt buffer\n");
      return Result::kFailure;
      // LCOV_EXCL_STOP
    }

    if (std::cmp_not_equal(outlen, len)) {
      // LCOV_EXCL_START
      ReportError("[Crypto] Decryption failed - Cannot decrypt buffer\n");
      return Result::kFailure;
      // LCOV_EXCL_STOP
    }
  }

  std::array<uint8_t, kBlockSize> final_block{};
  int final_len = 0;

  if (EVP_DecryptFinal_ex(ctx_, final_block.data(), &final_len) != 1) {
    ReportError("[Auth] Verification failed - File is corrupted or tampered\n");
    return Result::kFailure;
  }

  return Result::kSuccess;
}
