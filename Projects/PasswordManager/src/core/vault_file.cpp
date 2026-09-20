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
    Reset();  // The failure was before the rename, so nothing was published and no session may outlive the attempt
    return Result::kFailure;
  }

  return Result::kSuccess;
}

Result Vault::OpenVault(const std::string& path, const Password& pw) {
  std::set<Entry, EntryCmp> tmp;
  size_t cur = 0;
  uint32_t entry_cnt = 0;

  last_error_.clear();
  last_warning_.clear();

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
    ReportError("[File] Validation failed - File exceeds maximum size (4 MiB)\n");
    return Result::kFailure;
  }

  /* Read the header, and nothing else yet. Everything that decides whether this is a vault at all and whether this
   * password opens it lives in these bytes; the body is needed only once both have been answered. Keeping the
   * allocation and the read of up to 4 MiB behind those answers means a wrong magic number never buys them. What a
   * stranger can spend here is these kHeaderSize bytes and the one Argon2id pass Limitations names as the cost a
   * crafted file gets to choose, bounded by the range check ParseHeader applies. */

  std::array<uint8_t, kHeaderSize> head_buff{};

  if (fread(head_buff.data(), sizeof(uint8_t), head_buff.size(), file_) != head_buff.size()) {
    // LCOV_EXCL_START
    ReportError("[File] Read failed - Cannot read vault file data\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  /* Check and adopt the header. Magic, version and parameter ranges are settled in one place, so nothing here
   * re-checks what kOk already promises. */

  VaultHeader header;

  const HeaderStatus status = ParseHeader(head_buff, header);

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
   * damaged. The commitment derived beside the key answers the first question by itself, and it is compared here so
   * that every failure past this point means the file. */

  if (!key_->CommitmentMatches(header.commitment)) {
    Reset();
    ReportError("[Auth] Open failed - Incorrect master password\n");
    return Result::kFailure;
  }

  /* Read the rest of the vault, now that the header has been checked and the password answered for. The header bytes
   * are in hand already, so they are copied to the front of the buffer and the read picks up where it stopped, at
   * kHeaderSize. */

  const size_t src_bytes = static_cast<size_t>(src_size_);
  const size_t body_bytes = src_bytes - kHeaderSize;

  src_buff_.assign(src_bytes, 0);

  std::ranges::copy(head_buff, src_buff_.begin());

  if (fread(src_buff_.data() + kHeaderSize, sizeof(uint8_t), body_bytes, file_) != body_bytes) {
    // LCOV_EXCL_START
    Reset();
    ReportError("[File] Read failed - Cannot read vault file data\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  /* Decrypt into the session image */

  int64_t img_size = src_size_ - static_cast<int64_t>(kFrameSize);

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
   * have nowhere to disagree. The header arrives in a read of its own, but it is copied to the front of this buffer
   * byte for byte rather than rebuilt from what was parsed out of it, so what the tag covers is what the disk holds.
   * FileEncryption has to rebuild its header for this because it drops the buffer it read from; a vault keeps the
   * buffer it decrypts out of, so there is nothing to rebuild.
   *
   * The password was settled by the commitment above, which leaves damage as the only thing a failing tag can mean
   * here. */

  if (aes_.Decrypt(src_buff_.data() + kHeaderSize, img_.Data(), body_bytes, *key_,
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

  /* Divided rather than multiplied. entry_cnt is a uint32_t taken from the image, and kMinEntrySize times its
   * largest value is past what a 32-bit size_t holds, so the product would wrap to something small and let the
   * count through. Nothing unsafe follows from that, since the loop below refuses the first entry that does not
   * parse, but the check is here to refuse an impossible count before iterating on it and a wrapped product does
   * not do that. img_len is at least kCountSize, because kMinSize accounts for the count field and a shorter file
   * was refused above. */

  if (entry_cnt > (img_len - kCountSize) / kMinEntrySize) {
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
  last_warning_.clear();

  /* Confirm the image and the entry set still describe each other before encrypting. The pair checked here is the
   * installed one, which CommitImage has already verified; it is checked again because what is about to be written to
   * disk is these bytes, and a save is the last point at which a disagreement can still be caught instead of
   * stored. */

  if (VerifyImage(img_, entry_set_) == Result::kFailure) {
    return Result::kFailure;  // VerifyImage reported the error
  }

  /* Calculate file size. Every image that reaches this point is bounded already: NewVault builds a fixed four bytes,
   * OpenVault's came out of a file the kMaxSize check above let through, and CommitImage turns away anything past
   * kMaxImageSize. The exclusion below says unreachable and now means it. The check stays because this is the last
   * point at which an oversized image can be stopped rather than written, and a file past kMaxSize is one OpenVault
   * refuses, which would leave a vault this build wrote and cannot open. */

  dst_size_ = static_cast<int64_t>(kFrameSize + img_.Size());

  if (dst_size_ > kMaxSize) {
    // LCOV_EXCL_START
    ReportError("[Data] Validation failed - Vault exceeds maximum size (4 MiB)\n");
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

  if (OpenTempFile(&file_, tmp_path) == Result::kFailure) {
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

  /* Rename temporary file to vault file. This is the commit point: the rename is atomic, the vault it replaces is
   * gone the moment it returns, and nothing below can undo it. So nothing below may report the save as failed, since
   * a caller reads kFailure as a promise that the file on disk is the one it was before the call. */

  if (RenameFile(tmp_path, path) == Result::kFailure) {
    // LCOV_EXCL_START
    ReportError("[File] Rename failed - Cannot replace vault file\n");
    RemoveFile(tmp_path);
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  dirty_ = false;

  Clear();

  /* Sync the directory entry so the rename itself survives a crash. Failing here says the vault was published but
   * its directory entry may not outlive a power loss, which is a warning about durability rather than a save that
   * did not happen, and it is reported as one so the session can follow the file that is now on disk. */

  if (SyncDir(path) == Result::kFailure) {
    last_warning_ = "[File] Saved, but the directory entry could not be flushed to disk\n";
  }

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

  /* Persist with the new key before changing session state. SaveVaultWith fails only before its rename, so a failure
   * here means the file still belongs to the old key, and a success means it belongs to the new one whether or not
   * the directory entry could be flushed afterwards. The session key follows the file either way. */

  if (SaveVaultWith(path, *new_key) == Result::kFailure) {
    return Result::kFailure;
  }

  /* Commit the session state only after the save has succeeded */

  key_ = std::move(new_key);
  salt_ = new_salt;
  kdf_ = new_kdf;

  return Result::kSuccess;
}
