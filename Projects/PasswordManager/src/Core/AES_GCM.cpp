/**
 * @file	AES_GCM.cpp
 * @brief	Implementation of basic functions AES_GCM class
 * @author	Astatine387
 */

#include "Core/AES_GCM.h"

#include <openssl/err.h>

#include <cstring>

#include "Utils/library.h"

AesGcm::AesGcm() {
  memset(iv_, 0, sizeof(uint8_t) * kIVSize);
  memset(salt_, 0, sizeof(uint8_t) * kSaltSize);

  Lock(key_, kKeySize);
}

AesGcm::~AesGcm() {
  Wipe(iv_, sizeof(uint8_t) * kIVSize);
  Wipe(key_, sizeof(uint8_t) * kKeySize);
  Wipe(salt_, sizeof(uint8_t) * kSaltSize);

  Unlock(key_, kKeySize);

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