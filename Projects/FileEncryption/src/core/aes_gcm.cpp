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
#include <string>

AesGcm::AesGcm() {
  writer_ = std::thread(&AesGcm::WriterLoop, this);
}

// NOLINTNEXTLINE(bugprone-exception-escape)
AesGcm::~AesGcm() {
  /* Stop the writer thread, draining any ongoing write first */

  {
    std::scoped_lock lk(write_mtx_);
    writer_stop_ = true;
  }

  write_cv_.notify_one();

  if (writer_.joinable()) {
    writer_.join();
  }

  for (int i = 0; i < kBuffNum; i++) {
    sodium_memzero(buff_[i].data(), sizeof(buff_[i]));
  }

  sodium_memzero(iv_.data(), sizeof(iv_));
  sodium_memzero(salt_.data(), sizeof(salt_));
  sodium_memzero(tag_.data(), sizeof(tag_));

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
  std::unique_lock<std::mutex> lk(write_mtx_);

  for (;;) {
    write_cv_.wait(lk, [this] { return write_pending_ || writer_stop_; });

    /* Exit once a shutdown was requested and no job is left to drain */

    if (writer_stop_ && !write_pending_) {
      break;
    }

    const void* buff = write_buff_;
    size_t size = write_size_;

    /* Write outside the lock so the producer can keep reading and encrypting */

    lk.unlock();

    Result res = Result::kFailure;

    try {
      res = WriteFile(buff, size);
    }
    catch (...) {
      res = Result::kFailure;
    }

    lk.lock();

    if (res != Result::kSuccess) {
      write_result_ = res;  // Sticky: never mask a failure with a later success
    }

    write_pending_ = false;
    write_cv_.notify_one();
  }
}

Result AesGcm::SubmitWrite(const void* buff, size_t size) {
  std::unique_lock<std::mutex> lk(write_mtx_);

  /* Wait for the previous write to finish */

  write_cv_.wait(lk, [this] { return !write_pending_; });

  if (write_result_ != Result::kSuccess) {
    return Result::kFailure;  // LCOV_EXCL_LINE
  }

  /* Hand the new buffer to the writer thread */

  write_buff_ = buff;
  write_size_ = size;
  write_pending_ = true;

  lk.unlock();
  write_cv_.notify_one();

  return Result::kSuccess;
}

Result AesGcm::FlushWrite() {
  std::unique_lock<std::mutex> lk(write_mtx_);

  write_cv_.wait(lk, [this] { return !write_pending_; });

  return write_result_;
}

Progress AesGcm::ReportProgress() {
  if (pcb_) {
    int perc = static_cast<int>(progress_max_ > 0 ? progress_cur_ * 100 / progress_max_ : 100);

    bool should_cancel = false;

    pcb_(perc, &should_cancel);

    if (should_cancel) {
      return Progress::kCancelled;
    }
  }

  return Progress::kContinue;
}

void AesGcm::ReportError(const char* msg) {
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

  /* Serialize the callback so a write-thread error cannot race a read/encrypt-thread error */

  std::scoped_lock lk(error_mtx_);
  ecb_(res.c_str());
}