/**
 * @file	aes_gcm_enc.cpp
 * @brief	Implementation of encryption function of AES_GCM class
 * @author	Astatine387
 */

#include <algorithm>
#include <array>
#include <limits>
#include <utility>

#include "core/aes_gcm.h"
#include "utils/platform.h"

Result AesGcm::Encrypt(FILE* src, FILE* dst, const SecureKey& key, std::span<const uint8_t, kSaltSize> salt,
                       const KdfParams& params) {
  src_file_ = src;
  dst_file_ = dst;
  progress_cur_ = 0;
  last_perc_ = -1;
  key_ = &key;

  /* Drain any write left over from a previous (possibly aborted) run, then arm a clean result */

  FlushWrite();

  {
    UniqueLock lk(write_mtx_);
    write_result_ = Result::kSuccess;
  }

  /* Drain the writer on every exit path so the caller can safely close the destination file */

  WriterGuard writer_guard(this);

  if (EncryptInit(salt, params) == Result::kFailure) {
    return Result::kFailure;
  }

  if (EncryptLoop() == Result::kFailure) {
    return Result::kFailure;
  }

  return Result::kSuccess;
}

Result AesGcm::EncryptInit(std::span<const uint8_t, kSaltSize> salt, const KdfParams& params) {
  /* Get source file size */

  src_size_ = GetFileSize(src_file_);

  if (src_size_ == -1) {
    // LCOV_EXCL_START
    ReportError("[File] Size check failed - Cannot read source file size\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  /* Progress is reported over plaintext bytes; the file is read exactly once */

  progress_max_ = src_size_;

  /* Describe the file, then keep the serialized bytes as the associated data of every chunk */

  FileHeader header;

  header.chunk_log2 = kChunkSizeLog2;
  header.params = params;
  std::ranges::copy(salt, header.salt.begin());

  chunk_size_ = size_t{ 1 } << header.chunk_log2;

  SerializeHeader(header_, header);

  AllocBuffers();

  if (SetupCtx(CryptoMode::kEncrypt) == Result::kFailure) {
    return Result::kFailure;  // LCOV_EXCL_LINE
  }

  if (WriteFile(header_.data(), header_.size()) == Result::kFailure) {
    return Result::kFailure;  // LCOV_EXCL_LINE
  }

  return Result::kSuccess;
}

Result AesGcm::EncryptLoop() {
  int64_t rem = src_size_;
  uint64_t idx = 0;
  size_t cur = 0;

  /* A file always holds at least one chunk, so an empty plaintext still produces a tag */

  for (;;) {
    const bool is_last = std::cmp_less_equal(rem, chunk_size_);
    const size_t len = is_last ? static_cast<size_t>(rem) : chunk_size_;

    if (ReadFile(buff_[cur].data(), len) == Result::kFailure) {
      return Result::kFailure;  // LCOV_EXCL_LINE
    }

    if (EncryptChunk(buff_[cur].data(), len, idx, is_last) == Result::kFailure) {
      return Result::kFailure;  // LCOV_EXCL_LINE
    }

    /* Ciphertext and tag are contiguous, so a chunk leaves as a single write */

    if (SubmitWrite(buff_[cur].data(), len + kTagSize) == Result::kFailure) {
      return Result::kFailure;
    }

    /* Swap buffer */

    cur = 1 - cur;

    /* Update progress */

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

  /* Wait for the last write to finish */

  if (FlushWrite() == Result::kFailure) {
    return Result::kFailure;
  }

  return Result::kSuccess;
}

Result AesGcm::EncryptChunk(uint8_t* buff, size_t len, uint64_t idx, bool is_last) {
  BuildNonce(idx, is_last);

  /* Re-initialize the nonce */

  if (EVP_EncryptInit_ex(ctx_, nullptr, nullptr, nullptr, nonce_.data()) != 1) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Encryption failed - Cannot set chunk nonce\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  int outlen = 0;

  /* Authenticate the header before any plaintext */

  if (EVP_EncryptUpdate(ctx_, nullptr, &outlen, header_.data(), static_cast<int>(header_.size())) != 1) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Encryption failed - Cannot authenticate the header\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  if (len > 0) {
    if (EVP_EncryptUpdate(ctx_, buff, &outlen, buff, static_cast<int>(len)) != 1) {
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

  /* GCM emits nothing here */

  std::array<uint8_t, kBlockSize> final_block{};
  int final_len = 0;

  if (EVP_EncryptFinal_ex(ctx_, final_block.data(), &final_len) != 1) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Finalization failed - Cannot finalize encryption\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  /* Append the tag */

  if (EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_GCM_GET_TAG, static_cast<int>(kTagSize), buff + len) != 1) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Tag Error - Cannot get auth tag\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  return Result::kSuccess;
}
