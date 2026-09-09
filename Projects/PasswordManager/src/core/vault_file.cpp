/**
 * @file	vault_file.cpp
 * @brief	Implementation of file management functions of Vault class
 * @author	Astatine387
 */

#include <algorithm>
#include <array>
#include <span>

#include "core/vault.h"
#include "core/vault_header.h"
#include "utils/byte_order.h"
#include "utils/platform.h"

Result Vault::NewVault(const std::string& path, const Password& pw) {
  last_error_.clear();

  Reset();

  /* Generate a new salt */

  if (Random(salt_.data(), kSaltSize) == Result::kFailure) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Random failed - Cannot generate salt\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  /* Derive the session key */

  key_ = DeriveKey(std::span<const char>(pw.GetData(), pw.GetSize()), salt_, kdf_);

  if (!key_.has_value()) {
    // LCOV_EXCL_START
    Reset();
    ReportError("[Crypto] Key derivation failed - Argon2id error\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  /* Build the empty vault image */

  img_ = SecureBuffer(kCountSize);

  if (!img_.Valid()) {
    // LCOV_EXCL_START
    Reset();
    ReportError("[Memory] Allocation failed - Cannot allocate vault image\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  uint32_t entry_cnt = 0;

  StoreLE32(img_.Data(), entry_cnt);

  /* Encrypt and write the vault file atomically */

  if (SaveVaultWith(path, *key_) == Result::kFailure) {
    return Result::kFailure;  // LCOV_EXCL_LINE
  }

  return Result::kSuccess;
}

Result Vault::OpenVault(const std::string& path, const Password& pw) {
  std::set<Entry, EntryCmp> tmp;
  size_t cur = 0;
  uint32_t entry_cnt = 0;

  last_error_.clear();

  Reset();

  /* Open file pointer */

  OpenFile(&file_, path, "rb");

  if (file_ == nullptr) {
    ReportError("[File] Open failed - Cannot open vault file\n");
    return Result::kFailure;
  }

  /* Get vault size */

  src_size_ = GetFileSize(file_);

  if (src_size_ == -1) {
    // LCOV_EXCL_START
    ReportError("[File] Size check failed - Cannot read vault file size\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  if (src_size_ < kMinSize) {
    ReportError("[File] Validation failed - File is too small to be a valid vault\n");
    return Result::kFailure;
  }

  if (src_size_ > kMaxSize) {
    ReportError("[File] Validation failed - File exceeds maximum size (2 GiB)\n");
    return Result::kFailure;
  }

  /* Read vault */

  const size_t src_bytes = static_cast<size_t>(src_size_);

  src_buff_.assign(src_bytes, 0);

  if (fread(src_buff_.data(), sizeof(uint8_t), src_bytes, file_) != src_bytes) {
    // LCOV_EXCL_START
    ReportError("[File] Read failed - Cannot read vault file data\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  /* Check and adopt the header. Magic, version and parameter ranges are settled in one place, so nothing here
   * re-checks what kOk already promises. */

  VaultHeader header;

  const HeaderStatus status = ParseHeader(src_buff_, header);

  if (status != HeaderStatus::kOk) {
    ReportError(HeaderErrorMessage(status));
    return Result::kFailure;
  }

  salt_ = header.salt;
  kdf_ = header.params;

  /* Derive the session key under the derivation the header describes */

  key_ = DeriveKey(std::span<const char>(pw.GetData(), pw.GetSize()), salt_, kdf_);

  if (!key_.has_value()) {
    // LCOV_EXCL_START
    Reset();
    ReportError("[Crypto] Key derivation failed - Argon2id error\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  /* Settle which of the two failures this is before decrypting anything. AES-GCM does not commit to the key a tag
   * was verified under, so a failing tag on its own cannot say whether the password was wrong or the file was
   * damaged, and both used to be reported as one sentence. The commitment derived beside the key answers the first
   * question by itself, and it is compared here so that every failure past this point means the file. */

  if (!key_->CommitmentMatches(header.commitment)) {
    Reset();
    ReportError("[Auth] Open failed - Incorrect master password\n");
    return Result::kFailure;
  }

  /* Decrypt into the session image */

  int64_t img_size = src_size_ - static_cast<int64_t>(kHeaderSize + kIVSize + kTagSize);

  img_ = SecureBuffer(static_cast<size_t>(img_size));

  if (!img_.Valid()) {
    // LCOV_EXCL_START
    Reset();
    ReportError("[Memory] Allocation failed - Cannot allocate vault image\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  /* The associated data is a view into the buffer the file was read into, not a header re-serialized from the
   * fields just parsed out of it, so the bytes on the disk and the bytes under the tag are physically the same and
   * have nowhere to disagree. FileEncryption has to rebuild its header for this because it drops the buffer it read
   * from; a vault is read whole and kept, so there is nothing to rebuild.
   *
   * The password was settled by the commitment above, which leaves damage as the only thing a failing tag can mean
   * here. */

  if (aes_.Decrypt(src_buff_.data() + kHeaderSize, img_.Data(), src_bytes - kHeaderSize, *key_,
                   std::span(src_buff_.data(), kHeaderSize)) == Result::kFailure) {
    Reset();
    ReportError("[Auth] Open failed - Vault file is corrupted\n");
    return Result::kFailure;
  }

  /* Deserialize the entries from the image */

  const uint8_t* base = img_.Data();
  size_t img_len = img_.Size();

  entry_cnt = LoadLE32(base);
  cur += kCountSize;

  if (static_cast<size_t>(entry_cnt) * kMinEntrySize > img_len - kCountSize) {
    Reset();
    ReportError("[Data] Validation failed - Entry count exceeds available data\n");
    return Result::kFailure;
  }

  for (uint32_t i = 0; i < entry_cnt; i++) {
    Entry entry;

    size_t bytes = entry.Deserialize(base + cur, img_len - cur, cur);

    if (bytes == 0) {
      Reset();
      ReportError("[Data] Deserialization failed - Invalid entry data\n");
      return Result::kFailure;
    }

    cur += bytes;

    if (!tmp.insert(std::move(entry)).second) {
      Reset();
      ReportError("[Data] Validation failed - Duplicate entry in vault file\n");
      return Result::kFailure;
    }
  }

  entry_set_ = std::move(tmp);

  Clear();

  return Result::kSuccess;
}

Result Vault::SaveVault(const std::string& path) {
  last_error_.clear();

  if (!key_.has_value()) {
    ReportError("[Auth] Save failed - No vault is open\n");
    return Result::kFailure;
  }

  return SaveVaultWith(path, *key_);
}

Result Vault::SaveVaultWith(const std::string& path, const SecureKey& key) {
  /* Verify the image redzone and offset invariant before encrypting */

  if (VerifyImage() == Result::kFailure) {
    return Result::kFailure;  // VerifyImage reported the error
  }

  /* Calculate file size */

  dst_size_ = static_cast<int64_t>(kHeaderSize + kIVSize + img_.Size() + kTagSize);

  if (dst_size_ > kMaxSize) {
    // LCOV_EXCL_START
    ReportError("[Data] Validation failed - Vault exceeds maximum size (2 GiB)\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  const size_t dst_bytes = static_cast<size_t>(dst_size_);

  dst_buff_.assign(dst_bytes, 0);

  /* Describe the derivation from the key itself. Salt, parameters and commitment come from the one object that was
   * produced by the derivation being described, so the header cannot end up describing a different one. */

  VaultHeader header;

  header.params = key.Params();

  std::ranges::copy(key.Salt(), header.salt.begin());
  std::ranges::copy(key.Commitment(), header.commitment.begin());

  SerializeHeader(std::span<uint8_t, kHeaderSize>(dst_buff_.data(), kHeaderSize), header);

  /* Encrypt the image behind the header with a fresh IV, authenticating the header bytes just written. The span
   * passed as associated data is the buffer that goes to the disk rather than a second copy assembled from the same
   * fields, so what is written and what is authenticated are the same bytes. */

  if (aes_.Encrypt(img_.Data(), dst_buff_.data() + kHeaderSize, img_.Size(), key,
                   std::span(dst_buff_.data(), kHeaderSize)) == Result::kFailure) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Encryption failed - Cannot encrypt vault data\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  /* Save to a temporary file */

  std::string tmp_path = path + ".XXXXXX";

  if (OpenTempFile(&file_, tmp_path, path) == Result::kFailure) {
    ReportError("[File] Open failed - Cannot create temporary file for writing\n");
    return Result::kFailure;
  }

  if (fwrite(dst_buff_.data(), sizeof(uint8_t), dst_bytes, file_) != dst_bytes) {
    // LCOV_EXCL_START
    ReportError("[File] Write failed - Cannot write temporary file");
    RemoveFile(tmp_path);
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  /* Sync file data to disk */

  if (SyncFile(file_) == Result::kFailure) {
    // LCOV_EXCL_START
    ReportError("[File] Sync failed - Cannot flush vault file to disk\n");
    RemoveFile(tmp_path);
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  /* SyncFile above already flushed the stream and fsynced the descriptor, so every byte of the temporary file is on
   * disk before this runs and there is no deferred write left for fclose to report. What it can still return is a
   * close failure, which on Linux releases the descriptor either way and cannot take the data back; the rename below
   * is what publishes the file, and it is checked. */

  static_cast<void>(fclose(file_));
  file_ = nullptr;

  /* Rename temporary file to vault file */

  if (RenameFile(tmp_path, path) == Result::kFailure) {
    // LCOV_EXCL_START
    ReportError("[File] Rename failed - Cannot replace vault file\n");
    RemoveFile(tmp_path);
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  /* Sync the directory entry so the rename itself survives a crash */

  if (SyncDir(path) == Result::kFailure) {
    // LCOV_EXCL_START
    ReportError("[File] Sync failed - Cannot flush directory entry to disk\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  Clear();

  return Result::kSuccess;
}

void Vault::CloseVault() {
  Reset();
  Clear();
}

bool Vault::VerifyPW(const Password& pw) const {
  if (!key_.has_value()) {
    return false;
  }

  auto cand = DeriveKey(std::span<const char>(pw.GetData(), pw.GetSize()), salt_, kdf_);

  if (!cand.has_value()) {
    return false;  // LCOV_EXCL_LINE
  }

  /* Compared through the commitment rather than key against key, which is the same question the open path asks of a
   * header and keeps the derived key itself out of every comparison.
   *
   * This does not make verification cheaper: a full Argon2id derivation still runs here, and the change-password path
   * in MainGUI::OnChangePWRequested runs a second one inside ChangePW, so that flow pays for two. Collapsing them
   * belongs with the threading work rather than here. */

  return cand->CommitmentMatches(key_->Commitment());
}

Result Vault::ChangePW(const Password& pw, const std::string& path) {
  last_error_.clear();

  if (!key_.has_value()) {
    ReportError("[Auth] Password change failed - No vault is open\n");
    return Result::kFailure;
  }

  /* Generate a new salt */

  std::array<uint8_t, kSaltSize> new_salt{};

  if (Random(new_salt.data(), kSaltSize) == Result::kFailure) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Random failed - Cannot generate salt\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  /* Derive a new key with the current defaults, upgrading a vault written by an older build */

  const KdfParams new_kdf{};

  auto new_key = DeriveKey(std::span<const char>(pw.GetData(), pw.GetSize()), new_salt, new_kdf);

  if (!new_key.has_value()) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Key derivation failed - Argon2id error\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  /* Persist with the new key before changing session state */

  if (SaveVaultWith(path, *new_key) == Result::kFailure) {
    return Result::kFailure;  // LCOV_EXCL_LINE
  }

  /* Commit the session state only after the save has succeeded */

  key_ = std::move(new_key);
  salt_ = new_salt;
  kdf_ = new_kdf;

  return Result::kSuccess;
}
