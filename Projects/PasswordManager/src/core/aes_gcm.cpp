/**
 * @file	aes_gcm.cpp
 * @brief	Implementation of basic functions of AesGcm class
 * @author	Astatine387
 */

#include "core/aes_gcm.h"

#include <openssl/err.h>
#include <sodium.h>

#include <cstring>

AesGcm::~AesGcm() {
  sodium_memzero(iv_.data(), iv_.size());

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