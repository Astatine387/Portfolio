/**
 * @file    crypto_worker.cpp
 * @brief   Implementation of CryptoWorker class
 * @author  Astatine387
 */

#include "core/crypto_worker.h"

#include <array>
#include <memory>
#include <optional>
#include <span>
#include <string_view>
#include <utility>

#include "core/file_header.h"
#include "core/secure_key.h"
#include "utils/platform.h"

namespace {

constexpr std::string_view kPartSuffix = ".tmp";

}  // namespace

void CryptoWorker::RequestCancel() {
  cancel_->store(true, std::memory_order_relaxed);
}

void CryptoWorker::ReportPhase(WorkPhase phase, const std::string& status) {
  if (!phcb_) {
    return;
  }

  phcb_(phase, status);
}

void CryptoWorker::Work() {
  AesGcm aes;
  Result res;
  FILE* src_file = nullptr;
  FILE* dst_file = nullptr;
  std::string msg;
  bool should_delete = false;

  /* Write to a temporary file and move into destination at the end */

  std::string tmp_path = dst_path_;

  tmp_path += kPartSuffix;

  /* Use OpenSourceFile rather than a plain open so that a directory, a symbolic
   * link, or a pseudo fileis are refused instead of being read as an empty
   * source */

  if (OpenSourceFile(&src_file, src_path_) == Result::kFailure) {
    if (fcb_) {
      fcb_(
          "[File] Open failed - Cannot open source file, or it is not an "
          "ordinary file\n");
    }

    return;
  }

  /* Refuse a destination that is already taken */

  if (FileExists(dst_path_) ||
      OpenNewFile(&dst_file, tmp_path) == Result::kFailure) {
    static_cast<void>(fclose(src_file));

    if (fcb_) {
      fcb_(
          "[File] Open failed - Cannot create destination file, or it already "
          "exists\n");
    }

    return;
  }

  /* Read the file header */

  FileHeader header;
  std::optional<SecureKey> key;
  std::string reason;

  const int64_t src_size = GetFileSize(src_file);

  if (src_size == -1) {
    // LCOV_EXCL_START
    reason = "[File] Size check failed - Cannot read source file size\n";
    // LCOV_EXCL_STOP
  }
  else if (mode_ == CryptoMode::kEncrypt && src_size > kMaxPlaintextSize) {
    // LCOV_EXCL_START
    reason =
        "[File] Size check failed - Source file exceeds the supported "
        "maximum\n";
    // LCOV_EXCL_STOP
  }
  else if (mode_ == CryptoMode::kDecrypt) {
    const HeaderStatus status = ReadHeader(src_file, header);

    if (status != HeaderStatus::kOk) {
      reason = HeaderErrorMessage(status);
    }
    else if (std::cmp_less(src_size, kMinSize)) {
      reason =
          "[File] Validation failed - File is too small to be an encrypted "
          "file\n";
    }
  }

  /* Derive the session key */

  if (reason.empty()) {
    ReportPhase(WorkPhase::kDerivingKey, "Deriving key from password...\n");

    if (mode_ == CryptoMode::kEncrypt) {
      const KdfParams params;
      std::array<uint8_t, kSaltSize> salt{};

      if (Random(salt.data(), kSaltSize) == Result::kFailure) {
        // LCOV_EXCL_START
        reason =
            "[Crypto] Salt generation failed - Cannot obtain random bytes\n";
        // LCOV_EXCL_STOP
      }
      else {
        key = DeriveKey(std::span<const char>(pw_.GetData(), pw_.GetSize()),
                        salt, params);
      }
    }
    else {
      key = DeriveKey(std::span<const char>(pw_.GetData(), pw_.GetSize()),
                      header.salt, header.params);
    }
  }

  /* Free and wipe the password buffer */

  pw_ = Password();

  if (!key.has_value()) {
    static_cast<void>(fclose(src_file));
    static_cast<void>(fclose(dst_file));
    RemoveFile(tmp_path);

    if (reason.empty()) {
      reason = "[Crypto] Key derivation failed\n";
    }

    if (fcb_) {
      fcb_(reason + (mode_ == CryptoMode::kEncrypt ? "Encryption failed\n"
                                                   : "Decryption failed\n"));
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

  /* Do encrypt or decrypt */

  const std::string verb =
      mode_ == CryptoMode::kEncrypt ? "Encryption" : "Decryption";

  ReportPhase(WorkPhase::kProcessing, mode_ == CryptoMode::kEncrypt
                                          ? "Encrypting...\n"
                                          : "Decrypting...\n");

  if (mode_ == CryptoMode::kEncrypt) {
    res = aes.Encrypt(src_file, dst_file, *key);
  }
  else {
    res = aes.Decrypt(src_file, dst_file, *key, header);
  }

  static_cast<void>(fclose(src_file));

  /* Examine the result before the cancellation flag */

  if (res == Result::kFailure) {
    should_delete = true;

    msg = IsCancelled() ? verb + " cancelled\n" : err_ + verb + " failed\n";
  }
  else {
    ReportPhase(WorkPhase::kFinishing, "Flushing to disk, please wait...\n");

    if (SyncFile(dst_file) == Result::kFailure) {
      // LCOV_EXCL_START
      should_delete = true;
      msg = "[File] Sync failed - Cannot flush the destination to disk\n" +
            verb + " failed\n";
      // LCOV_EXCL_STOP
    }
  }

  if (fclose(dst_file) != 0 && !should_delete) {
    // LCOV_EXCL_START
    should_delete = true;
    msg =
        "[File] Close failed - Cannot complete the write to the destination\n" +
        verb + " failed\n";
    // LCOV_EXCL_STOP
  }

  /* Atomic write, don't report success while a power loss can still take the
   * data away */

  if (should_delete) {
    RemoveFile(tmp_path);
  }
  else if (RenameFile(tmp_path, dst_path_) == Result::kFailure) {
    RemoveFile(tmp_path);

    msg =
        "[File] Move failed - Destination already exists or cannot be "
        "written\n" +
        verb + " failed\n";
  }
  else if (SyncDir(dst_path_) == Result::kFailure) {
    msg = "[File] Sync failed - Cannot flush the destination directory\n" +
          verb + " completed\n";  // LCOV_EXCL_LINE
  }
  else {
    msg = verb + " complete\n";
  }

  if (fcb_) {
    fcb_(msg);
  }
}
