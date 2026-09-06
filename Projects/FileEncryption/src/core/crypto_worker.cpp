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
#include <string_view>

#include "core/file_header.h"
#include "core/secure_key.h"
#include "utils/platform.h"

namespace {

constexpr std::string_view kPartSuffix = ".tmp";

}  // namespace

void CryptoWorker::RequestCancel() {
  /* Relaxed is enough: the flag publishes no data, and the engine only reads it between chunks, so the
   * one thing that matters is that the store eventually becomes visible */

  cancel_->store(true, std::memory_order_relaxed);
}

void CryptoWorker::ReportPhase(WorkPhase phase, const std::string& status) {
  if (!phcb_) {
    return;
  }

  phcb_(phase, status);
}

void CryptoWorker::Work() {
  auto aes_ptr = std::make_unique<AesGcm>();
  AesGcm& aes = *aes_ptr;
  Result res;
  FILE* src_file = nullptr;
  FILE* dst_file = nullptr;
  std::string msg;
  bool should_delete = false;

  /* Everything is written to a sibling of the destination and moved into place at the end, so a run that
   * dies halfway leaves a .tmp file rather than a half-written destination. A sibling because RenameFile
   * cannot cross a filesystem. */

  std::string tmp_path = dst_path_;

  tmp_path += kPartSuffix;

  /* Source first, so a bad source path costs nothing and leaves nothing behind to clean up */

  OpenFile(&src_file, src_path_, "rb");

  if (src_file == nullptr) {
    if (fcb_) {
      fcb_("[File] Open failed - Cannot open source file\n");
    }

    return;
  }

  /* Refuse a destination that is already taken */

  if (FileExists(dst_path_) || OpenNewFile(&dst_file, tmp_path) == Result::kFailure) {
    fclose(src_file);

    if (fcb_) {
      fcb_("[File] Open failed - Cannot create destination file, or it already exists\n");
    }

    return;
  }

  /* Derive the session key. Encryption picks a fresh salt and keeps the default parameters; decryption
   * has to take both from the header, since they are what the file was written with. */

  std::array<uint8_t, kSaltSize> salt{};
  KdfParams params;
  std::optional<SecureKey> key;
  std::string reason;

  /* Argon2id holds this thread for as long as the parameters ask for and offers no way back out, so the
   * phase is announced before it starts rather than after it ends. On the decryption path those
   * parameters came out of the file, which is what makes the wait worth naming. */

  ReportPhase(WorkPhase::kDerivingKey, "Deriving key from password...\n");

  if (mode_ == CryptoMode::kEncrypt) {
    if (Random(salt.data(), kSaltSize) == Result::kSuccess) {
      key = DeriveKey(std::span<const char>(pw_.GetData(), pw_.GetSize()), salt, params);
    }
  }
  else {
    FileHeader header;

    const HeaderStatus status = ReadHeader(src_file, header);

    if (status == HeaderStatus::kOk) {
      salt = header.salt;
      params = header.params;

      key = DeriveKey(std::span<const char>(pw_.GetData(), pw_.GetSize()), salt, params);
    }
    else {
      reason = HeaderErrorMessage(status);
    }
  }

  /* Derivation is over either way, so let the password go here: assigning over it frees the secure
   * buffer, which wipes it, well before the long crypto pass begins */

  pw_ = Password();

  if (!key.has_value()) {
    fclose(src_file);
    fclose(dst_file);
    RemoveFile(tmp_path);

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

  const std::string verb = mode_ == CryptoMode::kEncrypt ? "Encryption" : "Decryption";

  /* The one phase the flag can stop, and the one with a percentage to report. It is announced before
   * the first chunk so that cancelling is offered before there is anything to cancel, and both reports
   * leave this thread in this order. */

  ReportPhase(WorkPhase::kProcessing, mode_ == CryptoMode::kEncrypt ? "Encrypting...\n" : "Decrypting...\n");

  if (mode_ == CryptoMode::kEncrypt) {
    res = aes.Encrypt(src_file, dst_file, *key, salt, params);
  }
  else {
    res = aes.Decrypt(src_file, dst_file, *key);
  }

  fclose(src_file);

  /* The result is examined before the cancellation flag. A cancel that arrives after the
   * work is already done must not throw away a complete and valid output. */

  if (res == Result::kFailure) {
    should_delete = true;

    msg = IsCancelled() ? verb + " cancelled\n" : err_ + verb + " failed\n";
  }
  else {
    /* Past the point where cancelling could mean anything: the ciphertext is complete and only has to be
     * made durable. The progress callback has already reported 100%, while fsync on a slow device is
     * where the run spends its last visible seconds, so the phase is what keeps that pause from reading
     * as a freeze at the end of the bar. */

    ReportPhase(WorkPhase::kFinishing, "Flushing to disk, please wait...\n");

    if (SyncFile(dst_file) == Result::kFailure) {
      // LCOV_EXCL_START
      should_delete = true;

      msg = "[File] Sync failed - Cannot flush the destination to disk\n" + verb + " failed\n";
      // LCOV_EXCL_STOP
    }
  }

  fclose(dst_file);

  /* Publish only once the bytes are on the disk, so success is never reported for data that
   * a power loss could still take away */

  if (should_delete) {
    RemoveFile(tmp_path);
  }
  else if (RenameFile(tmp_path, dst_path_) == Result::kFailure) {
    RemoveFile(tmp_path);

    msg = "[File] Move failed - Destination already exists or cannot be written\n" + verb + " failed\n";
  }
  else if (SyncDir(dst_path_) == Result::kFailure) {
    /* The data is already at the destination, so it stays; only its durability is in doubt */

    msg = "[File] Sync failed - Cannot flush the destination directory\n" + verb + " failed\n";  // LCOV_EXCL_LINE
  }
  else {
    msg = verb + " complete\n";
  }

  if (fcb_) {
    fcb_(msg);
  }
}
