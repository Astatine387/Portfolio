/**
 * @file	crypto_worker.cpp
 * @brief	Implementation of CryptoWorker class
 * @author	Astatine387
 */

#include "core/crypto_worker.h"

#include <array>
#include <memory>
#include <optional>
#include <span>

#include "core/file_header.h"
#include "core/secure_key.h"
#include "utils/platform.h"

void CryptoWorker::RequestCancel() {
  cancel_->store(true, std::memory_order_relaxed);
}

void CryptoWorker::Work() {
  /* Heap-allocated: AesGcm carries a 128 KiB buffer, too large for a worker thread's stack frame */

  auto aes_ptr = std::make_unique<AesGcm>();
  AesGcm& aes = *aes_ptr;

  FILE* src_file = nullptr;
  FILE* dst_file = nullptr;
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
  KdfParams params;
  std::optional<SecureKey> key;
  std::string reason;

  if (mode_ == CryptoMode::kEncrypt) {
    if (Random(salt.data(), kSaltSize) == Result::kSuccess) {
      key = DeriveKey(std::span<const char>(pw_.GetData(), pw_.GetSize()), salt, params);
    }
  }
  else {
    FileHeader header;

    HeaderStatus status = ReadHeader(src_file, header);

    if (status == HeaderStatus::kOk) {
      status = ValidateKdfParams(header.params);
    }

    if (status == HeaderStatus::kOk) {
      salt = header.salt;
      params = header.params;

      key = DeriveKey(std::span<const char>(pw_.GetData(), pw_.GetSize()), salt, params);
    }
    else {
      reason = HeaderErrorMessage(status);
    }
  }

  pw_ = Password();

  if (!key.has_value()) {
    fclose(src_file);
    fclose(dst_file);
    RemoveFile(dst_path_);

    if (reason.empty()) {
      reason = "[Crypto] Key derivation failed\n";
    }

    if (fcb_) {
      fcb_(reason + (mode_ == CryptoMode::kEncrypt ? "Encryption failed\n" : "Decryption failed\n"));
    }

    return;
  }

  /* Set up callbacks */

  aes.SetErrorCallback([this](const char* m) { err_ = m; });

  aes.SetCancelFlag(cancel_.get());

  aes.SetProgressCallback([this](int perc) {
    if (!pcb_) {
      return;
    }

    std::string status;

    if (mode_ == CryptoMode::kEncrypt) {
      status = "Encrypting... " + std::to_string(perc) + "%\n";
    }
    else {
      status = "Decrypting... " + std::to_string(perc) + "%\n";
    }

    pcb_(perc, status);
  });

  /* Encrypt or decrypt */

  if (mode_ == CryptoMode::kEncrypt) {
    res = aes.Encrypt(src_file, dst_file, *key, salt, params);

    if (IsCancelled()) {
      msg = "Encryption canceled\n";
      should_delete = true;
    }
    else if (res == Result::kFailure) {
      // LCOV_EXCL_START
      msg = err_ + "Encryption failed\n";
      should_delete = true;
      // LCOV_EXCL_STOP
    }
    else {
      msg = "Encryption complete\n";
    }
  }
  else {
    res = aes.Decrypt(src_file, dst_file, *key);

    if (IsCancelled()) {
      msg = "Decryption canceled\n";
      should_delete = true;
    }
    else if (res == Result::kFailure) {
      msg = err_ + "Decryption failed\n";
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
