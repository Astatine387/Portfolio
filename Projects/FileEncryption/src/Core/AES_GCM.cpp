/**
 * @file	AES_GCM.cpp
 * @brief	Implementation of basic functions of AES_GCM class
 * @author	Astatine387
 *
 * Contents:
 *	- Implementation of destructor and helper functions of AES_GCM class
 */

#include "Core/AES_GCM.h"

#include "Utils/library.h"

#include <openssl/err.h>

#include <cstring>

AesGcm::AesGcm() {
  for (int i = 0; i < kBuffNum; i++) {
    memset(buff_[i], 0, sizeof(uint8_t) * kBuffSize * kBlockSize);
  }

  memset(iv_, 0, sizeof(uint8_t) * kIVSize);
  memset(salt_, 0, sizeof(uint8_t) * kSaltSize);

  Lock(key_, kKeySize);
}

AesGcm::~AesGcm() {
  if (write_res_.valid()) {
    write_res_.wait();
  }

  for (int i = 0; i < kBuffNum; i++) {
    Wipe(buff_[i], sizeof(uint8_t) * kBuffSize * kBlockSize);
  }

  Wipe(iv_, sizeof(uint8_t) * kIVSize);
  Wipe(key_, sizeof(uint8_t) * kKeySize);
  Wipe(salt_, sizeof(uint8_t) * kSaltSize);

  Unlock(key_, kKeySize);

  if (ctx_) {
    EVP_CIPHER_CTX_free(ctx_);
    ctx_ = nullptr;
  }
}

int AesGcm::ReadFile(void* buff, int size) {
  if (fread(buff, sizeof(uint8_t), size, src_file_) != size) {
    // LCOV_EXCL_START
    ReportError("[File] Read failed - Cannot read source file data\n");
    return 1;
    // LCOV_EXCL_STOP
  }

  return 0;
}

int AesGcm::WriteFile(const void* buff, int size) {
  if (fwrite(buff, sizeof(uint8_t), size, dst_file_) != size) {
    // LCOV_EXCL_START
    if (ferror(dst_file_)) {
      ReportError("[File] Write failed - Disk may be full or I/O error\n");
    }
    else {
      ReportError("[File] Write failed - Cannot write destination file data\n");
    }

    return 1;
    // LCOV_EXCL_STOP
  }

  return 0;
}

int AesGcm::ReportProgress() {
  if (pcb_) {
    uint64_t perc = src_size_ > 0 ? progress_ * 100 / src_size_ : 100;

    bool should_cancel = false;

    pcb_(perc, &should_cancel);

    if (should_cancel) {
      cancelled_.store(true);
      return 1;
    }
  }

  return 0;
}

void AesGcm::ReportError(const char* msg) {
  if (!ecb_) {
    return;
  }

  std::string res;
  unsigned long code;
  char err_str[256];

  res += msg;

  while ((code = ERR_get_error()) != 0) {
    ERR_error_string_n(code, err_str, sizeof(err_str));

    res += " -> ";
    res += err_str;
    res += '\n';
  }

  ecb_(res.c_str());
}