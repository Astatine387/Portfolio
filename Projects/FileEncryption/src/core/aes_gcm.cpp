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

#include <array>
#include <string>

#include "utils/platform.h"

AesGcm::AesGcm() {
  key_locked_ = (Lock(key_.data(), kKeySize) == Result::kSuccess);
}

// NOLINTNEXTLINE(bugprone-exception-escape)
AesGcm::~AesGcm() {
  if (write_res_.valid()) {
    write_res_.wait();
  }

  for (int i = 0; i < kBuffNum; i++) {
    Wipe(buff_[i].data(), sizeof(buff_[i]));
  }

  Wipe(iv_.data(), sizeof(iv_));
  Wipe(key_.data(), sizeof(key_));
  Wipe(salt_.data(), sizeof(salt_));
  Wipe(tag_.data(), sizeof(tag_));

  if (key_locked_) {
    Unlock(key_.data(), kKeySize);
  }

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

Progress AesGcm::ReportProgress() {
  if (pcb_) {
    int perc = static_cast<int>(progress_max_ > 0 ? progress_cur_ * 100 / progress_max_ : 100);

    bool should_cancel = false;

    pcb_(perc, &should_cancel);

    if (should_cancel) {
      cancelled_.store(true);
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

  ecb_(res.c_str());
}