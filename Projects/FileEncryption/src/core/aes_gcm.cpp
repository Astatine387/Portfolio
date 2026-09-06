/**
 * @file	aes_gcm.cpp
 * @brief	Implementation of basic functions of AesGcm class
 * @author	Astatine387
 *
 * Contents:
 *	- Implementation of destructor and helper functions of AesGcm class
 */

#include "core/aes_gcm.h"

#include <openssl/err.h>
#include <sodium.h>

#include <array>
#include <atomic>
#include <string>
#include <vector>

#include "utils/byte_order.h"

namespace {

/* Nonce layout of the STREAM construction: zero padding, then the big-endian chunk counter, then the
 * final-chunk flag in the last byte */

constexpr size_t kCounterOffset = kNonceSize - 1 - sizeof(uint64_t);

constexpr uint8_t kNormalChunkFlag = 0x00;
constexpr uint8_t kFinalChunkFlag = 0x01;

static_assert(kCounterOffset + sizeof(uint64_t) + 1 == kNonceSize, "Nonce layout does not fill the nonce");

}  // namespace

AesGcm::AesGcm() {
  writer_ = std::thread(&AesGcm::WriterLoop, this);
}

/* Joining the writer and taking its lock can both throw std::system_error, which a destructor cannot
 * propagate; there would be nothing left to recover at this point either */

// NOLINTNEXTLINE(bugprone-exception-escape)
AesGcm::~AesGcm() {
  /* Stop the writer thread, draining any ongoing write first */

  {
    UniqueLock lk(write_mtx_);
    writer_stop_ = true;
  }

  write_cv_.NotifyOne();

  if (writer_.joinable()) {
    writer_.join();
  }

  for (std::vector<uint8_t>& buff : buff_) {
    if (!buff.empty()) {
      sodium_memzero(buff.data(), buff.size());
    }
  }

  sodium_memzero(nonce_.data(), nonce_.size());
  sodium_memzero(salt_.data(), salt_.size());

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

void AesGcm::WriterLoop() noexcept {
  /* One chunk is written while the next one is being read and encrypted. Only ever one job is queued,
   * so the producer owns whichever of the two buffers the writer is not holding. */

  UniqueLock lk(write_mtx_);

  for (;;) {
    write_cv_.Wait(lk, [this]() REQUIRES(write_mtx_) { return write_pending_ || writer_stop_; });

    /* Exit once a shutdown was requested and no job is left to drain */

    if (writer_stop_ && !write_pending_) {
      break;
    }

    const void* buff = write_buff_;
    size_t size = write_size_;

    /* Write outside the lock so the producer can keep reading and encrypting */

    lk.Unlock();

    Result res = Result::kFailure;

    try {
      res = WriteFile(buff, size);
    }
    catch (...) {
      res = Result::kFailure;
    }

    lk.Lock();

    if (res != Result::kSuccess) {
      write_result_ = res;  // Sticky: never mask a failure with a later success
    }

    write_pending_ = false;
    write_cv_.NotifyOne();
  }
}

Result AesGcm::SubmitWrite(const void* buff, size_t size) {
  UniqueLock lk(write_mtx_);

  /* Waiting here is what holds the pipeline to a single job: once it returns, the buffer handed over on
   * the previous call is free again, so the caller can rotate back into it */

  write_cv_.Wait(lk, [this]() REQUIRES(write_mtx_) { return !write_pending_; });

  if (write_result_ != Result::kSuccess) {
    return Result::kFailure;  // LCOV_EXCL_LINE
  }

  /* The buffer is borrowed, not copied, so the caller has to leave it alone until the next SubmitWrite
   * or FlushWrite returns */

  write_buff_ = buff;
  write_size_ = size;
  write_pending_ = true;

  lk.Unlock();
  write_cv_.NotifyOne();

  return Result::kSuccess;
}

Result AesGcm::FlushWrite() {
  /* Where a late failure surfaces: a write that failed after its SubmitWrite had already returned is
   * reported nowhere else */

  UniqueLock lk(write_mtx_);

  write_cv_.Wait(lk, [this]() REQUIRES(write_mtx_) { return !write_pending_; });

  return write_result_;
}

void AesGcm::ReportProgress() {
  if (!pcb_) {
    return;
  }

  int perc = static_cast<int>(progress_max_ > 0 ? progress_cur_ * 100 / progress_max_ : 100);

  /* A chunk is small enough that most of them do not move the percentage at all, and every report
   * crosses into the GUI thread, so only a whole percent is worth sending */

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
  /* Serialize the callback so a write-thread error cannot race a read/encrypt-thread error */

  UniqueLock lk(error_mtx_);

  if (!ecb_) {
    return;
  }

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

  ecb_(res.c_str());
}

void AesGcm::BuildNonce(uint64_t idx, bool is_last) {
  /* The counter gives every chunk a nonce of its own, so a reordered or duplicated chunk fails its tag,
   * and the flag binds where the file ends, so a truncated or extended one fails its tag too */

  nonce_.fill(0);

  StoreBE64(nonce_.data() + kCounterOffset, idx);

  nonce_[kNonceSize - 1] = is_last ? kFinalChunkFlag : kNormalChunkFlag;
}

void AesGcm::AllocBuffers() {
  /* Each buffer carries room for a tag past the chunk, so encryption can append the tag in place and a
   * whole chunk still leaves in one write */

  for (std::vector<uint8_t>& buff : buff_) {
    if (!buff.empty()) {
      sodium_memzero(buff.data(), buff.size());
    }

    buff.assign(chunk_size_ + kTagSize, 0);
  }
}

Result AesGcm::SetupCtx(CryptoMode mode) {
  /* One engine can serve more than one operation, so a context left over from the previous one goes
   * first */

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

  /* Three calls rather than one: OpenSSL takes the cipher first, then the nonce length, then the key.
   * Stating the length explicitly keeps the format independent of whatever the library defaults to. */

  const auto init = mode == CryptoMode::kEncrypt ? &EVP_EncryptInit_ex : &EVP_DecryptInit_ex;

  if (init(ctx_, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Initialization failed - Cannot set AES-256-GCM algorithm\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  if (EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(kNonceSize), nullptr) != 1) {
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
