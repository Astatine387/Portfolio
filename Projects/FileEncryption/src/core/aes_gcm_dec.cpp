/**
 * @file	aes_gcm_dec.cpp
 * @brief	Implementation of decryption function of AES_GCM class
 * @author	Astatine387
 */

#include <array>
#include <limits>
#include <utility>

#include "core/aes_gcm.h"
#include "utils/platform.h"

Result AesGcm::Decrypt(FILE* src, FILE* dst, const SecureKey& key, const FileHeader& header) {
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

  if (DecryptInit(header) == Result::kFailure) {
    return Result::kFailure;
  }

  if (DecryptLoop() == Result::kFailure) {
    return Result::kFailure;
  }

  return Result::kSuccess;
}

Result AesGcm::DecryptInit(const FileHeader& header) {
  src_size_ = GetFileSize(src_file_);

  if (src_size_ == -1) {
    // LCOV_EXCL_START
    ReportError("[File] Size check failed - Cannot read source file size\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  /* A file below the minimum cannot even hold a header and one tag */

  if (std::cmp_less(src_size_, kMinSize)) {
    ReportError("[File] Validation failed - File is too small to be an encrypted file\n");
    return Result::kFailure;
  }

  /* The header is not read here. The caller had to read it to derive the key at all, so reading it again would mean the
   * key came from one image of an untrusted file while the associated data, the chunk size and the commitment came from
   * another; nothing in the format ties two separate reads together. It arrives parsed instead, from the one read that
   * already happened.
   *
   * Re-validating it is not the same thing. ReadHeader is the caller's contract, this is defence in depth against a
   * caller that skipped it, and it costs a handful of comparisons on a struct that is already in memory rather than a
   * second trip to the disk. chunk_log2 is a shift width and sizes both buffers, and mem_cost has already been handed
   * to Argon2id by whoever derived the key. */

  const HeaderStatus status = ValidateHeader(header);

  if (status != HeaderStatus::kOk) {
    ReportError(HeaderErrorMessage(status));
    return Result::kFailure;
  }

  /* AES-GCM authenticates a chunk without committing to the key, so a tag that verifies says the chunk
   * was made under this key and not that no other key would have done. A crafted file can carry a tag
   * that solves under two passwords at once, and per-chunk tags do not narrow that: a chunk is thousands
   * of blocks, so each equation is solved on its own with blocks to spare. Feeding the header in as
   * associated data does not narrow it either, since the header is a constant the attacker knows.
   *
   * The commitment settles it outside the AEAD. It is checked here, before SerializeHeader, AllocBuffers
   * or SetupCtx, so a wrong password costs nothing beyond the derivation that had to happen anyway, and
   * every caller of this engine is covered rather than only the ones that remember to ask.
   *
   * What it cannot settle is which of the two sides moved, since a wrong password and an edited commitment
   * both end with the derived key disagreeing with the header, so the message below has to name both. */

  if (!key_->CommitmentMatches(header.commitment)) {
    ReportError("[Auth] Verification failed - Wrong password, or the file header has been modified\n");
    return Result::kFailure;
  }

  chunk_size_ = size_t{ 1 } << header.chunk_log2;

  /* The associated data has to be byte for byte what encryption fed in. The layout covers every byte of the header, so
   * re-emitting the validated struct reproduces exactly what the caller read, and nothing has to hold on to the raw
   * read buffer. */

  SerializeHeader(header_, header);

  /* Progress is reported over consumed ciphertext, tags included */

  src_size_ -= static_cast<int64_t>(kHeaderSize);

  progress_max_ = src_size_;

  AllocBuffers();

  if (SetupCtx(CryptoMode::kDecrypt) == Result::kFailure) {
    return Result::kFailure;  // LCOV_EXCL_LINE
  }

  /* The caller's read left the position wherever it left it, and this call never moved it. Positioning the first chunk
   * explicitly is what keeps the loop independent of how the header was read. */

  if (Seek(src_file_, static_cast<int64_t>(kHeaderSize), SEEK_SET) == Result::kFailure) {
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
    /* A trailing fragment too short to hold a tag is corruption */

    if (std::cmp_less(rem, kTagSize)) {
      ReportError("[File] Validation failed - Encrypted file is truncated or corrupted\n");
      return Result::kFailure;
    }

    /* Position alone decides the flag, so a truncated file arrives here with a chunk that was encrypted
     * as an interior one and is now verified as the final one, and its tag fails */

    const bool is_last = std::cmp_less_equal(rem, chunk_size_ + kTagSize);
    const size_t len = is_last ? static_cast<size_t>(rem) - kTagSize : chunk_size_;

    if (ReadFile(buff_[cur].data(), len + kTagSize) == Result::kFailure) {
      return Result::kFailure;  // LCOV_EXCL_LINE
    }

    if (DecryptChunk(buff_[cur].data(), len, idx, is_last) == Result::kFailure) {
      return Result::kFailure;
    }

    /* With the chunk authenticated, may the plaintext reach the disk */

    if (SubmitWrite(buff_[cur].data(), len) == Result::kFailure) {
      return Result::kFailure;
    }

    /* The writer still holds the buffer just submitted, so the next chunk goes into the other one */

    cur = 1 - cur;

    rem -= static_cast<int64_t>(len + kTagSize);
    progress_cur_ += static_cast<int64_t>(len + kTagSize);

    ReportProgress();

    if (IsCancelled()) {
      FlushWrite();
      return Result::kFailure;
    }

    if (idx == std::numeric_limits<uint64_t>::max()) {
      // LCOV_EXCL_START  unreachable: 2^64 chunks of at least 4 KiB cannot fit in a file
      ReportError("[Crypto] Decryption failed - Chunk counter overflow\n");
      return Result::kFailure;
      // LCOV_EXCL_STOP
    }

    idx++;
  }

  /* The loop leaves one chunk still in flight, and a failure on that last write is reported here */

  if (FlushWrite() == Result::kFailure) {
    return Result::kFailure;
  }

  return Result::kSuccess;
}

Result AesGcm::DecryptChunk(uint8_t* buff, size_t len, uint64_t idx, bool is_last) {
  BuildNonce(idx, is_last);

  /* Cipher and key stay as SetupCtx left them and only the nonce moves, so the key schedule is computed
   * once for the whole file rather than once per chunk */

  if (EVP_DecryptInit_ex(ctx_, nullptr, nullptr, nullptr, nonce_.data()) != 1) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Decryption failed - Cannot set chunk nonce\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  int outlen = 0;

  /* A null output buffer feeds the header in as associated data, the same way encryption did, so a
   * header edited after the fact fails the tag of every chunk rather than only the first */

  if (EVP_DecryptUpdate(ctx_, nullptr, &outlen, header_.data(), static_cast<int>(header_.size())) != 1) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Decryption failed - Cannot authenticate the header\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  /* The expected tag sits at buff + len, right behind the ciphertext the chunk was read into. It has to
   * be in the context before EVP_DecryptFinal_ex checks it, and this is where the chunk is configured. */

  if (EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_GCM_SET_TAG, static_cast<int>(kTagSize), buff + len) != 1) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Tag failed - Cannot set authentication tag\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  if (len > 0) {
    /* Same buffer in and out: the plaintext overwrites the ciphertext it came from, so a chunk needs no
     * second buffer. It is still unverified at this point. */

    if (EVP_DecryptUpdate(ctx_, buff, &outlen, buff, static_cast<int>(len)) != 1) {
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

  /* The tag is only checked here. Everything DecryptUpdate produced above is unauthenticated until this
   * call returns, which is why the caller writes nothing before DecryptChunk succeeds. */

  std::array<uint8_t, kBlockSize> final_block{};
  int final_len = 0;

  if (EVP_DecryptFinal_ex(ctx_, final_block.data(), &final_len) != 1) {
    /* A wrong password no longer reaches this point: DecryptInit rejected it against the commitment
     * before a chunk was read. That check cannot tell a wrong password from a commitment an attacker
     * rewrote, and nothing could: both leave the derived key disagreeing with the 32 bytes in the header,
     * which is one observation and not two. What it does separate is a header that does not name this key
     * from a chunk that does not match the header it was authenticated under, and those two are distinct,
     * which is why the message here blames the file rather than the password. */

    ReportError("[Auth] Verification failed - File is corrupted or tampered\n");
    return Result::kFailure;
  }

  return Result::kSuccess;
}
