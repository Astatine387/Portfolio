/**
 * @file	aes_gcm.cpp
 * @brief	Implementation of basic functions of AesGcm class
 * @author	Astatine387
 */

#include "core/aes_gcm.h"

#include <openssl/err.h>

#include <cstring>

#include "utils/platform.h"

AesGcm::AesGcm() {
  key_locked_ = (Lock(key_.data(), kKeySize) == Result::kSuccess);
}

AesGcm::~AesGcm() {
  Wipe(iv_.data(), sizeof(uint8_t) * kIVSize);
  Wipe(key_.data(), sizeof(uint8_t) * kKeySize);
  Wipe(salt_.data(), sizeof(uint8_t) * kSaltSize);
  Wipe(verify_buff_.data(), verify_buff_.size());

  Unlock(key_.data(), kKeySize);

  if (ctx_) {
    EVP_CIPHER_CTX_free(ctx_);
    ctx_ = nullptr;
  }
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