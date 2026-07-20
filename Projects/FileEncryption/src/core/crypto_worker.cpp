/**
 * @file	crypto_worker.cpp
 * @brief	Implementation of CryptoWorker class
 * @author	Astatine387
 */

#include "core/crypto_worker.h"

#include <array>
#include <optional>
#include <span>

#include "core/secure_key.h"
#include "utils/platform.h"

void CryptoWorker::RequestCancel() {
  should_cancel_.store(true, std::memory_order_release);
}

void CryptoWorker::Work() {
  AesGcm aes;
  FILE* src_file = nullptr;
  FILE* dst_file = nullptr;
  std::string err;
  std::string msg;
  bool should_delete = false;
  Result res;

  /* Open files */

  OpenFile(&src_file, src_path_, "rb");

  if (src_file == nullptr) {
    if (fcb_) {
      fcb_("[File] Open failed - Cannot open source file\n");
    }

    return;
  }

  OpenFile(&dst_file, dst_path_, "wb+");

  if (dst_file == nullptr) {
    fclose(src_file);

    if (fcb_) {
      fcb_("[File] Open failed - Cannot create destination file\n");
    }

    return;
  }

  /* Derive the session key */

  std::array<uint8_t, kSaltSize> salt{};
  std::optional<SecureKey> key;

  if (mode_ == CryptoMode::kEncrypt) {
    if (Random(salt.data(), kSaltSize) == Result::kSuccess) {
      key = DeriveKey(std::span<const char>(pw_.GetData(), pw_.GetSize()), salt);
    }
  }
  else {
    if (fread(salt.data(), sizeof(uint8_t), kSaltSize, src_file) == kSaltSize &&
        Seek(src_file, 0, SEEK_SET) == Result::kSuccess) {
      key = DeriveKey(std::span<const char>(pw_.GetData(), pw_.GetSize()), salt);
    }
  }

  pw_ = Password();

  if (!key.has_value()) {
    fclose(src_file);
    fclose(dst_file);
    RemoveFile(dst_path_);

    if (fcb_) {
      fcb_(mode_ == CryptoMode::kEncrypt ? "[Crypto] Key derivation failed\nEncryption failed\n"
                                         : "[Crypto] Key derivation failed\nDecryption failed\n");
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
    res = aes.Encrypt(src_file, dst_file, *key, salt);

    if (should_cancel_) {
      msg = "Encryption canceled\n";
      should_delete = true;
    }
    else if (res == Result::kFailure) {
      // LCOV_EXCL_START
      msg = err + "Encryption failed\n";
      should_delete = true;
      // LCOV_EXCL_STOP
    }
    else {
      msg = "Encryption complete\n";
    }
  }
  else {
    res = aes.Decrypt(src_file, dst_file, *key);

    if (should_cancel_) {
      msg = "Decryption canceled\n";
      should_delete = true;
    }
    else if (res == Result::kFailure) {
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
    fcb_(msg);
  }
}
