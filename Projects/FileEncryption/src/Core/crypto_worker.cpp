/**
 * @file	crypto_worker.cpp
 * @brief	Implementation of CryptoWorker class
 * @author	Astatine387
 */

#include "Core/crypto_worker.h"

#include "Utils/platform.h"

void CryptoWorker::RequestCancel() {
  should_cancel_.store(true, std::memory_order_release);
}

void CryptoWorker::Work() {
  AesGcm aes;
  FILE* src_file = nullptr;
  FILE* dst_file = nullptr;
  std::string err, msg;
  bool should_delete = false;
  int res;

  /* Abort if the password is not locked in memory */

  if (!pw_.IsLocked()) {
    if (fcb_) {
      fcb_("[Memory] Lock failed - Cannot lock password in memory\n", false);
    }

    return;
  }

  /* Open files */

  OpenFile(&src_file, src_path_, "rb");

  if (src_file == nullptr) {
    if (fcb_) {
      fcb_("[File] Open failed - Cannot open source file\n", false);
    }

    return;
  }

  OpenFile(&dst_file, dst_path_, "wb+");

  if (dst_file == nullptr) {
    fclose(src_file);

    if (fcb_) {
      fcb_("[File] Open failed - Cannot create destination file\n", false);
    }

    return;
  }

  /* Set up callbacks */

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

  /* Encrypt or decrypt */

  if (mode_ == CryptoMode::kEncrypt) {
    res = aes.Encrypt(src_file, dst_file, pw_.GetData(), pw_.GetSize());

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
    res = aes.Decrypt(src_file, dst_file, pw_.GetData(), pw_.GetSize());

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

  /* Close files */

  fclose(src_file);
  fclose(dst_file);

  /* Delete destination file on failure */

  if (should_delete) {
    RemoveFile(dst_path_);
  }

  if (fcb_) {
    fcb_(msg, false);
  }
}