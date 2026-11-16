/**
 * @file    vault_file.cpp
 * @brief   Implementation of file management functions of Vault class
 * @author  Astatine387
 */

#include <algorithm>
#include <array>
#include <span>

#include "core/vault.h"
#include "core/vault_header.h"
#include "utils/byte_order.h"
#include "utils/platform.h"

static_assert(
    kMaxSize == 4000LL * 1024,
    "The vault ceiling moved away from the 4,000 KiB these messages state");

Result Vault::NewVault(const std::string& path, const Password& pw) {
  last_error_.clear();

  if (FileExists(path)) {
    ReportError("[File] Create failed - A file already exists at this path\n");
    return Result::kFailure;
  }

  Reset();

  /* Generate a new salt */

  if (Random(salt_.data(), kSaltSize) == Result::kFailure) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Random failed - Cannot generate salt\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  /* Derive the session key */

  key_ =
      DeriveKey(std::span<const char>(pw.GetData(), pw.GetSize()), salt_, kdf_);

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

  if (SaveVaultWith(path, *key_, PublishMode::kCreateOnly,
                    SaveMode::kRefuseChanged) != SaveResult::kSuccess) {
    Reset();
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

  /* Resolve the path before it is opened */

  std::string real_path;

  if (ResolvePath(path, real_path) == Result::kFailure) {
    ReportError(
        "[File] Open failed - Cannot open vault file, or it is not an ordinary "
        "file\n");
    return Result::kFailure;
  }

  /* Open file pointer */

  if (OpenRegularFile(&file_, real_path) == Result::kFailure) {
    ReportError(
        "[File] Open failed - Cannot open vault file, or it is not an ordinary "
        "file\n");
    return Result::kFailure;
  }

  /* Get vault size and check it */

  src_size_ = GetFileSize(file_);

  if (src_size_ == -1) {
    // LCOV_EXCL_START
    ReportError("[File] Size check failed - Cannot read vault file size\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  if (src_size_ < kMinSize) {
    ReportError(
        "[File] Validation failed - File is too small to be a valid vault\n");
    return Result::kFailure;
  }

  if (src_size_ > kMaxSize) {
    ReportError(
        "[File] Validation failed - File exceeds maximum size (4,000 KiB)\n");
    return Result::kFailure;
  }

  /* Read the header */

  std::array<uint8_t, kHeaderSize> head_buff{};

  if (fread(head_buff.data(), sizeof(uint8_t), head_buff.size(), file_) !=
      head_buff.size()) {
    // LCOV_EXCL_START
    ReportError("[File] Read failed - Cannot read vault file data\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  /* Check and adopt the header */

  VaultHeader header;

  const HeaderStatus status = ParseHeader(head_buff, header);

  if (status != HeaderStatus::kOk) {
    ReportError(HeaderErrorMessage(status));
    return Result::kFailure;
  }

  salt_ = header.salt;
  kdf_ = header.params;

  /* Derive the session key under the derivation the header describes */

  key_ =
      DeriveKey(std::span<const char>(pw.GetData(), pw.GetSize()), salt_, kdf_);

  if (!key_.has_value()) {
    // LCOV_EXCL_START
    Reset();
    ReportError("[Crypto] Key derivation failed - Argon2id error\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  /* Check key commitment */

  if (!key_->CommitmentMatches(header.commitment)) {
    Reset();
    ReportError(
        "[Auth] Open failed - Incorrect master password, or the vault header "
        "has been modified\n");
    return Result::kFailure;
  }

  /* Read the rest of the vault */

  const size_t src_bytes = static_cast<size_t>(src_size_);
  const size_t body_bytes = src_bytes - kHeaderSize;

  src_buff_.assign(src_bytes, 0);

  std::ranges::copy(head_buff, src_buff_.begin());

  if (fread(src_buff_.data() + kHeaderSize, sizeof(uint8_t), body_bytes,
            file_) != body_bytes) {
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

  if (aes_.Decrypt(src_buff_.data() + kHeaderSize, img_.Data(), body_bytes,
                   *key_, std::span(src_buff_.data(), kHeaderSize)) ==
      Result::kFailure) {
    Reset();
    ReportError("[Auth] Open failed - Vault file is corrupted\n");
    return Result::kFailure;
  }

  /* Deserialize the entries from the image */

  const uint8_t* base = img_.Data();
  size_t img_len = img_.Size();

  entry_cnt = LoadLE32(base);
  cur += kCountSize;

  if (entry_cnt > (img_len - kCountSize) / kMinEntrySize) {
    Reset();
    ReportError(
        "[Data] Validation failed - Entry count exceeds available data\n");
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

  if (VerifyImage(img_, tmp, ImageOrigin::kFile) == Result::kFailure) {
    Reset();
    return Result::kFailure;  // VerifyImage reported the error
  }

  entry_set_ = std::move(tmp);

  RememberFile(path, real_path,
               std::span<const uint8_t, kIVSize>(src_buff_.data() + kHeaderSize,
                                                 kIVSize));

  Clear();

  return Result::kSuccess;
}

SaveResult Vault::SaveVault(const std::string& path, SaveMode mode) {
  last_error_.clear();

  if (!key_.has_value()) {
    ReportError("[Auth] Save failed - No vault is open\n");
    return SaveResult::kError;
  }

  return SaveVaultWith(path, *key_, PublishMode::kReplace, mode);
}

Vault::FileState Vault::ReadFileState(const std::string& path) {
  FileState state;
  FILE* file = nullptr;

  state.file = path;

  if (OpenRegularFile(&file, path) == Result::kFailure) {
    state.exists = FileExists(path);

    return state;
  }

  state.exists = true;

  constexpr int64_t kIVEnd = static_cast<int64_t>(kHeaderSize + kIVSize);

  std::array<uint8_t, kIVSize> iv{};

  const int64_t size = GetFileSize(file);

  if (size >= kIVEnd &&
      fseek(file, static_cast<long>(kHeaderSize), SEEK_SET) == 0 &&
      fread(iv.data(), sizeof(uint8_t), iv.size(), file) == iv.size()) {
    state.iv = iv;
    state.has_iv = true;
  }

  static_cast<void>(fclose(file));

  return state;
}

void Vault::RememberFile(const std::string& path, const std::string& real_path,
                         std::span<const uint8_t, kIVSize> iv) {
  FileMark mark;

  mark.path = path;
  mark.real_path = real_path;

  std::ranges::copy(iv, mark.iv.begin());

  mark_ = std::move(mark);
  ack_.reset();
}

std::string Vault::ReplaceTarget(const std::string& path) const {
  std::string real_path;

  if (ResolvePath(path, real_path) == Result::kSuccess) {
    return real_path;
  }

  if (mark_.has_value() && mark_->path == path) {
    return mark_->real_path;
  }

  return path;
}

SaveResult Vault::CheckTarget(const std::string& path,
                              const std::string& dst, SaveMode mode) {
  if (mode == SaveMode::kRefuseChanged) {
    ack_.reset();
  }

  const FileState state = ReadFileState(dst);

  const bool changed = (mark_.has_value() && mark_->path == path)
                           ? (dst != mark_->real_path || !state.has_iv ||
                              state.iv != mark_->iv)
                           : state.exists;

  if (!changed) {
    return SaveResult::kSuccess;
  }

  if (mode == SaveMode::kOverwriteAcknowledged && ack_.has_value() &&
      ack_->path == path && ack_->state == state) {
    return SaveResult::kSuccess;
  }

  ack_ = Conflict{ .path = path, .state = state };

  ReportError(
      "[File] Save refused - The vault file changed on disk after this session "
      "read or wrote it\n");

  return SaveResult::kConflict;
}

SaveResult Vault::SaveVaultWith(const std::string& path, const SecureKey& key,
                                PublishMode mode, SaveMode save) {
  last_warning_.clear();

  /* Confirm the image and the entry set still describe each other */

  if (VerifyImage(img_, entry_set_, ImageOrigin::kSession) ==
      Result::kFailure) {
    return SaveResult::kError;  // VerifyImage reported the error
  }

  /* Calculate file size */

  dst_size_ = static_cast<int64_t>(kFrameSize + img_.Size());

  if (dst_size_ > kMaxSize) {
    // LCOV_EXCL_START
    ReportError(
        "[Data] Validation failed - Vault exceeds maximum size (4,000 KiB)\n");
    return SaveResult::kError;
    // LCOV_EXCL_STOP
  }

  const size_t dst_bytes = static_cast<size_t>(dst_size_);

  dst_buff_.assign(dst_bytes, 0);

  /* Describe the derivation from the key */

  VaultHeader header;

  header.params = key.Params();

  std::ranges::copy(key.Salt(), header.salt.begin());
  std::ranges::copy(key.Commitment(), header.commitment.begin());

  SerializeHeader(
      std::span<uint8_t, kHeaderSize>(dst_buff_.data(), kHeaderSize), header);

  /* Encrypt the image behind the header with a fresh IV */

  if (aes_.Encrypt(img_.Data(), dst_buff_.data() + kHeaderSize, img_.Size(),
                   key, std::span(dst_buff_.data(), kHeaderSize)) ==
      Result::kFailure) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Encryption failed - Cannot encrypt vault data\n");
    return SaveResult::kError;
    // LCOV_EXCL_STOP
  }

  const std::string target =
      (mode == PublishMode::kReplace) ? ReplaceTarget(path) : path;

  /* Save to a temporary file */

  std::string tmp_path = target + ".XXXXXX";

  if (OpenTempFile(&file_, tmp_path) == Result::kFailure) {
    ReportError(
        "[File] Open failed - Cannot create temporary file for writing\n");
    return SaveResult::kError;
  }

  if (fwrite(dst_buff_.data(), sizeof(uint8_t), dst_bytes, file_) !=
      dst_bytes) {
    // LCOV_EXCL_START
    ReportError("[File] Write failed - Cannot write temporary file");
    RemoveFile(tmp_path);
    return SaveResult::kError;
    // LCOV_EXCL_STOP
  }

  /* Sync file data to disk */

  if (SyncFile(file_) == Result::kFailure) {
    // LCOV_EXCL_START
    ReportError("[File] Sync failed - Cannot flush vault file to disk\n");
    RemoveFile(tmp_path);
    return SaveResult::kError;
    // LCOV_EXCL_STOP
  }

  static_cast<void>(fclose(file_));
  file_ = nullptr;

  if (mode == PublishMode::kReplace) {
    const SaveResult check = CheckTarget(path, target, save);

    if (check != SaveResult::kSuccess) {
      RemoveFile(tmp_path);
      return check;  // CheckTarget reported the refusal
    }
  }

  /* Rename the temporary onto the file being published */

  if (mode == PublishMode::kCreateOnly) {
    const RenameStatus status = RenameFileNoReplace(tmp_path, path);

    if (status != RenameStatus::kOk) {
      RemoveFile(tmp_path);

      if (status == RenameStatus::kExists) {
        ReportError(
            "[File] Create failed - The path was taken before the vault could "
            "be written\n");
        return SaveResult::kError;
      }

      // LCOV_EXCL_START
      ReportError("[File] Create failed - Cannot publish the new vault file\n");
      return SaveResult::kError;
      // LCOV_EXCL_STOP
    }
  }
  else if (RenameFile(tmp_path, target) == Result::kFailure) {
    // LCOV_EXCL_START
    ReportError("[File] Rename failed - Cannot replace vault file\n");
    RemoveFile(tmp_path);
    return SaveResult::kError;
    // LCOV_EXCL_STOP
  }

  dirty_ = false;

  std::string real_path = target;

  if (target == path) {
    static_cast<void>(ResolvePath(path, real_path));
  }

  RememberFile(path, real_path,
               std::span<const uint8_t, kIVSize>(dst_buff_.data() + kHeaderSize,
                                                 kIVSize));

  Clear();

  /* Sync the directory entry */

  if (SyncDir(target) == Result::kFailure) {
    last_warning_ =
        "[File] Saved, but the directory entry could not be flushed to disk\n";
  }

  return SaveResult::kSuccess;
}

void Vault::CloseVault() {
  Reset();
  Clear();
}

bool Vault::VerifyPW(const Password& pw) const {
  if (!key_.has_value()) {
    return false;
  }

  auto cand =
      DeriveKey(std::span<const char>(pw.GetData(), pw.GetSize()), salt_, kdf_);

  if (!cand.has_value()) {
    return false;  // LCOV_EXCL_LINE
  }

  return cand->CommitmentMatches(key_->Commitment());
}

SaveResult Vault::ChangePW(const Password& pw, const std::string& path,
                           SaveMode mode) {
  last_error_.clear();

  if (!key_.has_value()) {
    ReportError("[Auth] Password change failed - No vault is open\n");
    return SaveResult::kError;
  }

  if (CheckTarget(path, ReplaceTarget(path), mode) == SaveResult::kConflict) {
    return SaveResult::kConflict;  // CheckTarget reported the refusal
  }

  /* Generate a new salt */

  std::array<uint8_t, kSaltSize> new_salt{};

  if (Random(new_salt.data(), kSaltSize) == Result::kFailure) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Random failed - Cannot generate salt\n");
    return SaveResult::kError;
    // LCOV_EXCL_STOP
  }

  /* Derive a new key with the current defaults */

  const KdfParams new_kdf{};

  auto new_key = DeriveKey(std::span<const char>(pw.GetData(), pw.GetSize()),
                           new_salt, new_kdf);

  if (!new_key.has_value()) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Key derivation failed - Argon2id error\n");
    return SaveResult::kError;
    // LCOV_EXCL_STOP
  }

  const SaveResult res =
      SaveVaultWith(path, *new_key, PublishMode::kReplace, mode);

  if (res != SaveResult::kSuccess) {
    return res;
  }

  /* Commit the session state only after the save has succeeded */

  key_ = std::move(new_key);
  salt_ = new_salt;
  kdf_ = new_kdf;

  return SaveResult::kSuccess;
}
