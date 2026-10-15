/**
 * @file    aes_gcm_enc.cpp
 * @brief   Implementation of encryption function of AES_GCM class
 * @author  Astatine387
 */

#include <algorithm>
#include <array>
#include <limits>
#include <utility>

#include "core/aes_gcm.h"
#include "utils/platform.h"

Result AesGcm::Encrypt(FILE* src, FILE* dst, const SecureKey& key) {
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

  /* Write the header, prepare the context and buffers */

  if (EncryptInit() == Result::kFailure) {
    return Result::kFailure;
  }

  /* Encrypt and write the file */

  if (EncryptLoop() == Result::kFailure) {
    return Result::kFailure;
  }

  return Result::kSuccess;
}

Result AesGcm::EncryptInit() {
  /* Check file size */

  src_size_ = GetFileSize(src_file_);

  if (src_size_ == -1) {
    // LCOV_EXCL_START
    ReportError("[File] Size check failed - Cannot read source file size\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  if (src_size_ > kMaxPlaintextSize) {
    // LCOV_EXCL_START
    ReportError(
        "[File] Size check failed - Source file exceeds the supported "
        "maximum\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  progress_max_ = src_size_;

  /* Create file header */

  FileHeader header;

  header.chunk_log2 = kChunkSizeLog2;
  header.params = key_->Params();
  std::ranges::copy(key_->Salt(), header.salt.begin());
  std::ranges::copy(key_->Commitment(), header.commitment.begin());
  chunk_size_ = size_t{ 1 } << header.chunk_log2;

  SerializeHeader(header_, header);

  AllocBuffers();

  /* Create a context and set the session key */

  if (SetupCtx(CryptoMode::kEncrypt) == Result::kFailure) {
    return Result::kFailure;  // LCOV_EXCL_LINE
  }

  /* Write the header */

  if (WriteFile(header_.data(), header_.size()) == Result::kFailure) {
    return Result::kFailure;  // LCOV_EXCL_LINE
  }

  return Result::kSuccess;
}

Result AesGcm::EncryptLoop() {
  int64_t rem = src_size_;
  uint64_t idx = 0;
  size_t cur = 0;

  for (;;) {
    const bool is_last = std::cmp_less_equal(rem, chunk_size_);
    const size_t len = is_last ? static_cast<size_t>(rem) : chunk_size_;

    if (ReadFile(buff_[cur].data(), len) == Result::kFailure) {
      return Result::kFailure;  // LCOV_EXCL_LINE
    }

    if (EncryptChunk(buff_[cur].data(), len, idx, is_last) ==
        Result::kFailure) {
      return Result::kFailure;  // LCOV_EXCL_LINE
    }

    if (SubmitWrite(buff_[cur].data(), len + kTagSize) == Result::kFailure) {
      return Result::kFailure;
    }

    cur = 1 - cur;

    rem -= static_cast<int64_t>(len);
    progress_cur_ += static_cast<int64_t>(len);

    ReportProgress();

    if (IsCancelled()) {
      FlushWrite();
      return Result::kFailure;
    }

    if (is_last) {
      break;
    }

    if (idx == std::numeric_limits<uint64_t>::max()) {
      // LCOV_EXCL_START
      ReportError("[Crypto] Encryption failed - Chunk counter overflow\n");
      return Result::kFailure;
      // LCOV_EXCL_STOP
    }

    idx++;
  }

  /* Fails if the source file size has been increased during encryption */

  uint8_t extra = 0;

  if (fread(&extra, sizeof(extra), 1, src_file_) != 0) {
    ReportError("[File] Encryption failed - Source file size changed\n");
    return Result::kFailure;
  }

  /* Wait for the ongoing write to finish */

  if (FlushWrite() == Result::kFailure) {
    return Result::kFailure;
  }

  return Result::kSuccess;
}

Result AesGcm::EncryptChunk(uint8_t* buff, size_t len, uint64_t idx,
                            bool is_last) {
  BuildNonce(idx, is_last);

  if (EVP_EncryptInit_ex(ctx_, nullptr, nullptr, nullptr, nonce_.data()) != 1) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Encryption failed - Cannot set chunk nonce\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  int outlen = 0;

  if (EVP_EncryptUpdate(ctx_, nullptr, &outlen, header_.data(),
                        static_cast<int>(header_.size())) != 1) {
    // LCOV_EXCL_START
    ReportError(
        "[Crypto] Encryption failed - Cannot authenticate the header\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  if (len > 0) {
    /* Same buffer in and out: the ciphertext overwrites the plaintext, which
     * leaves no second copy of the plaintext in memory and no second buffer to
     * allocate */

    if (EVP_EncryptUpdate(ctx_, buff, &outlen, buff, static_cast<int>(len)) !=
        1) {
      // LCOV_EXCL_START
      ReportError("[Crypto] Encryption failed - Cannot encrypt buffer\n");
      return Result::kFailure;
      // LCOV_EXCL_STOP
    }

    if (std::cmp_not_equal(outlen, len)) {
      // LCOV_EXCL_START
      ReportError("[Crypto] Encryption failed - Cannot encrypt buffer\n");
      return Result::kFailure;
      // LCOV_EXCL_STOP
    }
  }

  std::array<uint8_t, kBlockSize> final_block{};
  int final_len = 0;

  if (EVP_EncryptFinal_ex(ctx_, final_block.data(), &final_len) != 1) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Finalization failed - Cannot finalize encryption\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  if (EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_GCM_GET_TAG,
                          static_cast<int>(kTagSize), buff + len) != 1) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Tag Error - Cannot get auth tag\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  return Result::kSuccess;
}
