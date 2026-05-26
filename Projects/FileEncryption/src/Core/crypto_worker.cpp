/**
 * @file	crypto_worker.cpp
 * @brief	Implementation of CryptoWorker class
 * @author	Astatine387
 */

#include "crypto_worker.h"

void CryptoWorker::RequestCancel() {
  should_cancel_.store(true, std::memory_order_release);
}

void CryptoWorker::Work() {
  AesGcm aes;
  std::string err, msg;
  bool should_delete = false;
  int res;

  aes.SetErrorCallback([&err](const char* m) { err = m; });

  aes.SetProgressCallback([this](int perc, bool* cancelled) {
    if (pcb_) {
      std::string status;

      if (mode_ == CryptoMode::kEncrypt) {
        status = "Encrypting... " + std::to_string(perc) + "%\n";
      }
      else {
        status = "Decrypting... " + std::to_string(perc) + "%\n";
      }

      pcb_(perc, status);
    }

    *cancelled = should_cancel_.load(std::memory_order_acquire);
  });

  if (mode_ == CryptoMode::kEncrypt) {
    res = aes.Encrypt(src_file_, dst_file_, pw_.GetData(), pw_.GetSize());

    if (should_cancel_) {
      msg = "Encryption canceled\n";
      should_delete = true;
    }
    else if (res) {
      msg = err + "Encryption failed\n";
      should_delete = true;
    }
    else {
      msg = "Encryption complete\n";
    }
  }
  else {
    res = aes.Decrypt(src_file_, dst_file_, pw_.GetData(), pw_.GetSize());

    if (should_cancel_) {
      msg = "Decryption canceled\n";
      should_delete = true;
    }
    else if (res) {
      msg = err + "Decryption failed\n";
      should_delete = true;
    }
    else {
      msg = "Decryption complete\n";
    }
  }

  if (fcb_) {
    fcb_(msg, should_delete);
  }
}