/**
 * @file    aes_gcm.cpp
 * @brief   Implementation of basic functions of AesGcm class
 * @author  Astatine387
 */

#include "core/aes_gcm.h"

#include <openssl/err.h>
#include <sodium.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <limits>
#include <string>
#include <vector>

#include "utils/byte_order.h"

namespace {

/* Nonce layout: zero padding, big-endian chunk counter, and final-chunk flag */

constexpr size_t kCounterOffset = kNonceSize - 1 - sizeof(uint64_t);

constexpr uint8_t kNormalChunkFlag = 0x00;
constexpr uint8_t kFinalChunkFlag = 0x01;

static_assert(kCounterOffset + sizeof(uint64_t) + 1 == kNonceSize,
              "Nonce layout does not fill the nonce");

}  // namespace

AesGcm::AesGcm() {
  consumer_ = std::thread(&AesGcm::ConsumerLoop, this);
}

// NOLINTNEXTLINE(bugprone-exception-escape)
AesGcm::~AesGcm() {
  /* Acquire the lock and poll the stop flag for the consumer thread */

  {
    UniqueLock lk(write_mtx_);
    consumer_stop_ = true;
  }

  /* Wake the consumer thread */

  write_cv_.NotifyOne();

  /* Wait until the consumer thread finishes any remaining job */

  if (consumer_.joinable()) {
    consumer_.join();
  }

  /* Wipe the buffers */

  for (std::vector<uint8_t>& buff : buff_) {
    if (!buff.empty()) {
      sodium_memzero(buff.data(), buff.size());
    }
  }

  sodium_memzero(nonce_.data(), nonce_.size());

  /* Release the context */

  if (ctx_) {
    EVP_CIPHER_CTX_free(ctx_);
    ctx_ = nullptr;
  }
}

Result AesGcm::ReadFile(void* buff, size_t size) {
  if (fread(buff, sizeof(uint8_t), size, src_file_) != size) {
    // LCOV_EXCL_START
    ReportError("[File] Read failed - Cannot read source file data\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  return Result::kSuccess;
}

Result AesGcm::WriteFile(const void* buff, size_t size) {
  if (fwrite(buff, sizeof(uint8_t), size, dst_file_) != size) {
    // LCOV_EXCL_START
    if (ferror(dst_file_)) {
      ReportError("[File] Write failed - Disk may be full or I/O error\n");
    }
    else {
      ReportError("[File] Write failed - Cannot write destination file data\n");
    }

    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  return Result::kSuccess;
}

void AesGcm::ConsumerLoop() noexcept {
  /* Acquire the lock */

  UniqueLock lk(write_mtx_);

  for (;;) {
    /* Sleep until a job is queued or a quit is requested */

    write_cv_.Wait(lk, [this]() REQUIRES(write_mtx_) {
      return write_pending_ || consumer_stop_;
    });

    /* Stop once a quit is requested and no job is left */

    if (consumer_stop_ && !write_pending_) {
      break;
    }

    /* Get buffer address and size */

    const void* buff = write_buff_;
    size_t size = write_size_;

    /* Release the lock and write */

    lk.Unlock();

    Result res = Result::kFailure;

    try {
      res = WriteFile(buff, size);
    }
    catch (...) {
      res = Result::kFailure;
    }

    /* Acquire the lock again and record the result */

    lk.Lock();

    if (res != Result::kSuccess) {
      write_result_ = res;  // Sticky: never mask a failure with a later success
    }

    /* Wake the producer thread */

    write_pending_ = false;
    write_cv_.NotifyOne();
  }
}

Result AesGcm::SubmitWrite(const void* buff, size_t size) {
  /* Acquire the lock */

  UniqueLock lk(write_mtx_);

  /* Wait until the ongoing write finishes */

  write_cv_.Wait(lk, [this]() REQUIRES(write_mtx_) { return !write_pending_; });

  if (write_result_ != Result::kSuccess) {
    return Result::kFailure;  // LCOV_EXCL_LINE
  }

  /* Fill the slots */

  write_buff_ = buff;
  write_size_ = size;
  write_pending_ = true;

  /* Release the lock and wake the consumer thread */

  lk.Unlock();
  write_cv_.NotifyOne();

  return Result::kSuccess;
}

Result AesGcm::FlushWrite() {
  /* Acquire the lock */

  UniqueLock lk(write_mtx_);

  /* Wait until the ongoing write finishes */

  write_cv_.Wait(lk, [this]() REQUIRES(write_mtx_) { return !write_pending_; });

  return write_result_;
}

void AesGcm::ReportProgress() {
  if (!pcb_) {
    return;
  }

  int perc = 100;

  if (progress_max_ > 0) {
    const int64_t cur = std::min(progress_cur_, progress_max_);

    perc = static_cast<int>(cur <= std::numeric_limits<int64_t>::max() / 100
                                ? cur * 100 / progress_max_
                                : cur / (progress_max_ / 100));
  }

  /* Report only the percent changes */

  if (perc == last_perc_) {
    return;
  }

  last_perc_ = perc;

  pcb_(perc);
}

bool AesGcm::IsCancelled() const {
  return cancel_ != nullptr && cancel_->load(std::memory_order_relaxed);
}

void AesGcm::ReportError(const char* msg) {
  /* Acquire the lock */

  UniqueLock lk(error_mtx_);

  if (!ecb_) {
    return;
  }

  /* Assemble the error message */

  std::string res;
  unsigned long code;
  std::array<char, 256> err_str{};

  res += msg;

  while ((code = ERR_get_error()) != 0) {
    ERR_error_string_n(code, err_str.data(), err_str.size());

    res += " -> ";
    res += err_str.data();
    res += '\n';
  }

  /* Report error */

  ecb_(res.c_str());
}

void AesGcm::BuildNonce(uint64_t idx, bool is_last) {
  nonce_.fill(0);
  StoreBE64(nonce_.data() + kCounterOffset, idx);
  nonce_[kNonceSize - 1] = is_last ? kFinalChunkFlag : kNormalChunkFlag;
}

void AesGcm::AllocBuffers() {
  for (std::vector<uint8_t>& buff : buff_) {
    if (!buff.empty()) {
      sodium_memzero(buff.data(), buff.size());
    }

    buff.assign(chunk_size_ + kTagSize, 0);
  }
}

Result AesGcm::SetupCtx(CryptoMode mode) {
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

  const auto init =
      mode == CryptoMode::kEncrypt ? &EVP_EncryptInit_ex : &EVP_DecryptInit_ex;

  if (init(ctx_, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
    // LCOV_EXCL_START
    ReportError(
        "[Crypto] Initialization failed - Cannot set AES-256-GCM algorithm\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  if (EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_GCM_SET_IVLEN,
                          static_cast<int>(kNonceSize), nullptr) != 1) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Initialization failed - Cannot set nonce size\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  if (init(ctx_, nullptr, nullptr, key_->Bytes().data(), nullptr) != 1) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Initialization failed - Cannot set key\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  return Result::kSuccess;
}
