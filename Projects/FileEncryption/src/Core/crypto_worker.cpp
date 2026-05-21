/**
 * @file	crypto_worker.cpp
 * @brief	Implementation of Worker class
 * @author	Astatine387
 */

#include "crypto_worker.h"

void CryptoWorker::RequestCancel() {
  should_cancel_.store(true, std::memory_order_release);
}

void CryptoWorker::Work() {
  AesGcm aes;
  QString msg;
  bool should_delete = false;
  int res;

  aes.SetErrorCallback([this](const char* msg) { err_ = QString(msg); });

  aes.SetProgressCallback([this](int perc, bool* cancelled) {
    QString status;

    if (mode_ == CryptoMode::kEncrypt) {
      status = QString("Encrypting... %1%\n").arg(perc);
    }
    else {
      status = QString("Decrypting... %1%\n").arg(perc);
    }

    emit ProgressUpdate(perc, status);

    *cancelled = should_cancel_.load(std::memory_order_acquire);
  });

  if (mode_ == CryptoMode::kEncrypt) {
    res = aes.Encrypt(src_file_, dst_file_, pw_.GetData(), pw_.GetSize());

    if (should_cancel_) {
      msg = "Encryption canceled\n";
      should_delete = true;
    }
    else if (res) {
      msg = err_ + "Encryption failed\n";
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
      msg = err_ + "Decryption failed\n";
      should_delete = true;
    }
    else {
      msg = "Decryption complete\n";
    }
  }

  emit Finished(msg, should_delete);
}