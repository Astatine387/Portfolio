/**
 * @file	vault_file.cpp
 * @brief	Implementation of file management functions of Vault class
 * @author	Astatine387
 */

#include <cstring>

#include "core/vault.h"
#include "utils/platform.h"

Result Vault::NewVault(const std::string& path) {
  uint32_t entry_cnt = 0;

  last_error_.clear();

  /* Generate initial data */

  src_size_ = static_cast<int64_t>(kCountSize);
  dst_size_ = static_cast<int64_t>(kMagicSize + kSaltSize + kIVSize + src_size_ + kTagSize);

  src_buff_.assign(src_size_, 0);
  dst_buff_.assign(dst_size_, 0);

  memcpy(src_buff_.data(), &entry_cnt, kCountSize);
  memcpy(dst_buff_.data(), &magic_num_, kMagicSize);

  /* Encrypt */

  if (aes_.Encrypt(src_buff_.data(), dst_buff_.data() + kMagicSize, src_size_, pw_.GetData(), pw_.GetSize()) ==
      Result::kFailure) {
    ReportError("[Crypto] Encryption failed - Cannot encrypt vault data\n");
    return Result::kFailure;
  }

  /* Write vault */

  OpenFile(&file_, path, "wb");

  if (file_ == nullptr) {
    // LCOV_EXCL_START
    ReportError("[File] Open failed - Cannot create vault file\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  if (fwrite(dst_buff_.data(), sizeof(uint8_t), dst_size_, file_) != dst_size_) {
    // LCOV_EXCL_START
    ReportError("[File] Write failed - Cannot write vault file\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  /* Sync file data to disk */

  if (SyncFile(file_) == Result::kFailure) {
    // LCOV_EXCL_START
    ReportError("[File] Sync failed - Cannot flush vault file to disk\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  Clear();

  return Result::kSuccess;
}

Result Vault::OpenVault(const std::string& path) {
  std::set<Entry, EntryCmp> tmp;
  size_t cur = 0;
  uint32_t entry_cnt = 0;

  last_error_.clear();

  /* Open file pointer */

  OpenFile(&file_, path, "rb");

  if (file_ == nullptr) {
    // LCOV_EXCL_START
    ReportError("[File] Open failed - Cannot open vault file\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
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

  src_buff_.assign(src_size_, 0);

  if (fread(src_buff_.data(), sizeof(uint8_t), src_size_, file_) != src_size_) {
    // LCOV_EXCL_START
    ReportError("[File] Read failed - Cannot read vault file data\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  /* Check magic number */

  if (memcmp(src_buff_.data(), &magic_num_, kMagicSize) != 0) {
    ReportError("[File] Validation failed - Invalid vault file format\n");
    return Result::kFailure;
  }

  /* Decrypt */

  dst_size_ = static_cast<int64_t>(src_size_ - (kMagicSize + kSaltSize + kIVSize + kTagSize));

  dst_buff_.assign(dst_size_, 0);

  if (aes_.Decrypt(src_buff_.data() + kMagicSize, dst_buff_.data(), src_size_ - kMagicSize, pw_.GetData(),
                   pw_.GetSize()) == Result::kFailure) {
    ReportError("[Auth] Decryption failed - Invalid password or corrupted vault\n");
    return Result::kFailure;
  }

  /* Deserialize */

  memcpy(&entry_cnt, dst_buff_.data(), kCountSize);
  cur += kCountSize;

  if (entry_cnt * kMinEntrySize > dst_size_ - kCountSize) {
    ReportError("[Data] Validation failed - Entry count exceeds available data\n");
    return Result::kFailure;
  }

  for (uint32_t i = 0; i < entry_cnt; i++) {
    Entry entry;

    size_t bytes = entry.Deser(dst_buff_.data() + cur, dst_size_ - cur);

    if (bytes == 0) {
      ReportError("[Data] Deserialization failed - Invalid entry data\n");
      return Result::kFailure;
    }

    cur += bytes;

    tmp.insert(std::move(entry));
  }

  entry_set_ = std::move(tmp);

  Clear();

  return Result::kSuccess;
}

Result Vault::SaveVault(const std::string& path) {
  size_t src_cur = 0, dst_cur = 0;
  uint32_t entry_cnt = static_cast<uint32_t>(entry_set_.size());

  last_error_.clear();

  /* Calculate vault size */

  src_size_ = sizeof(uint32_t);

  for (const auto& entry : entry_set_) {
    src_size_ += static_cast<int64_t>(entry.Size());
  }

  dst_size_ = static_cast<int64_t>(kMagicSize + kSaltSize + kIVSize + src_size_ + kTagSize);

  /* Check whether the vault exceeds the maximum size */

  if (dst_size_ > kMaxSize) {
    ReportError("[Data] Validation failed - Vault exceeds maximum size (2 GiB)\n");
    return Result::kFailure;
  }

  src_buff_.assign(src_size_, 0);
  dst_buff_.assign(dst_size_, 0);

  /* Write entry count to buffer */

  memcpy(src_buff_.data() + src_cur, &entry_cnt, sizeof(uint32_t));
  src_cur += sizeof(uint32_t);

  /* Write entries to buffer */

  for (const auto& entry : entry_set_) {
    src_cur += entry.Ser(src_buff_.data() + src_cur);
  }

  memcpy(dst_buff_.data() + dst_cur, &magic_num_, kMagicSize);
  dst_cur += kMagicSize;

  /* Encrypt */

  if (aes_.Encrypt(src_buff_.data(), dst_buff_.data() + dst_cur, src_size_, pw_.GetData(), pw_.GetSize()) ==
      Result::kFailure) {
    ReportError("[Crypto] Encryption failed - Cannot encrypt vault data\n");
    return Result::kFailure;
  }

  /* Save to temporary file */

  std::string tmp_path = path + ".tmp";

  OpenFile(&file_, tmp_path, "wb");

  if (file_ == nullptr) {
    // LCOV_EXCL_START
    ReportError("[File] Open failed - Cannot open temporary file for writing\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  if (fwrite(dst_buff_.data(), sizeof(uint8_t), dst_size_, file_) != dst_size_) {
    // LCOV_EXCL_START
    ReportError("[File] Write failed - Cannot write temporary file\n");
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

  fclose(file_);
  file_ = nullptr;

  /* Rename temporary file to vault file */

  if (RenameFile(tmp_path, path) == Result::kFailure) {
    // LCOV_EXCL_START
    ReportError("[File] Rename failed - Cannot replace vault file\n");
    RemoveFile(tmp_path);
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  Clear();

  return Result::kSuccess;
}

void Vault::CloseVault() {
  entry_set_.clear();
  pw_.Clean();
  Clear();
}

bool Vault::VerifyPW(const Password& pw) const {
  return pw_.Equal(pw);
}

Result Vault::ChangePW(const Password& pw, const std::string& path) {
  last_error_.clear();

  if (pw_.SetData(pw) == Result::kFailure) {
    ReportError(
        "[Auth] Password change failed - Password exceeds maximum length (256 "
        "characters)\n");
    return Result::kFailure;
  }

  if (SaveVault(path) == Result::kFailure) {
    return Result::kFailure;  // LCOV_EXCL_LINE
  }

  return Result::kSuccess;
}

void Vault::SetPW(const Password& pw) {
  pw_ = pw;
}