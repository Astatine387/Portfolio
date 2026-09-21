/**
 * @file	aes_gcm.cpp
 * @brief	Implementation of basic functions of AesGcm class
 * @author	Astatine387
 */

#include "core/aes_gcm.h"

#include <openssl/err.h>

#include <string>

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
