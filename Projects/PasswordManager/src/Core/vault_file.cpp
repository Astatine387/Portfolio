/**
 * @file	vault_file.cpp
 * @brief	Implementation of file management functions of Vault class
 * @author	Astatine387
 */

#include "Core/Vault.h"
#include "Utils/library.h"

int Vault::NewVault(const QString& path) {
  uint32_t entry_cnt = 0;

  last_error_.clear();

  /* Generate initial data */

  src_size_ = kCountSize;
  dst_size_ = kMagicSize + kSaltSize + kIVSize + src_size_ + kTagSize;

  src_buff_ = std::make_unique<uint8_t[]>(src_size_);
  dst_buff_ = std::make_unique<uint8_t[]>(dst_size_);

  memcpy(src_buff_.get(), &entry_cnt, kCountSize);
  memcpy(dst_buff_.get(), &magic_num_, kMagicSize);

  /* Encrypt */

  if (aes_.Encrypt(src_buff_.get(), dst_buff_.get() + kMagicSize, src_size_,
                   pw_.GetData(), pw_.GetSize())) {
    ReportError("[Crypto] Encryption failed - Cannot encrypt vault data\n");
    return 1;
  }

  /* Write vault */

  OpenFile(&file_, path, "wb");

  if (file_ == nullptr) {
    // LCOV_EXCL_START
    ReportError("[File] Open failed - Cannot create vault file\n");
    return 1;
    // LCOV_EXCL_STOP
  }

  if (fwrite(dst_buff_.get(), sizeof(uint8_t), dst_size_, file_) != dst_size_) {
    // LCOV_EXCL_START
    ReportError("[File] Write failed - Cannot write vault file\n");
    return 1;
    // LCOV_EXCL_STOP
  }

  /* Sync file data to disk */

  if (SyncFile(file_)) {
    // LCOV_EXCL_START
    ReportError("[File] Sync failed - Cannot flush vault file to disk\n");
    return 1;
    // LCOV_EXCL_STOP
  }

  Clear();

  return 0;
}

int Vault::OpenVault(const QString& path) {
  std::set<Entry, EntryCmp> tmp;
  size_t cur = 0;
  uint32_t entry_cnt = 0;

  last_error_.clear();

  /* Open file pointer */

  OpenFile(&file_, path, "rb");

  if (file_ == nullptr) {
    // LCOV_EXCL_START
    ReportError("[File] Open failed - Cannot open vault file\n");
    return 1;
    // LCOV_EXCL_STOP
  }

  /* Get vault size */

  src_size_ = GetFileSize(file_);

  if (src_size_ == -1) {
    // LCOV_EXCL_START
    ReportError("[File] Size check failed - Cannot read vault file size\n");
    return 1;
    // LCOV_EXCL_STOP
  }

  if (src_size_ < kMinSize) {
    ReportError(
        "[File] Validation failed - File is too small to be a valid vault\n");
    return 1;
  }

  if (src_size_ > kMaxSize) {
    ReportError(
        "[File] Validation failed - File exceeds maximum size (2 GiB)\n");
    return 1;
  }

  /* Read vault */

  src_buff_ = std::make_unique<uint8_t[]>(src_size_);

  if (fread(src_buff_.get(), sizeof(uint8_t), src_size_, file_) != src_size_) {
    // LCOV_EXCL_START
    ReportError("[File] Read failed - Cannot read vault file data\n");
    return 1;
    // LCOV_EXCL_STOP
  }

  /* Check magic number */

  if (memcmp(src_buff_.get(), &magic_num_, kMagicSize) != 0) {
    ReportError("[File] Validation failed - Invalid vault file format\n");
    return 1;
  }

  /* Decrypt */

  dst_size_ = src_size_ - (kMagicSize + kSaltSize + kIVSize + kTagSize);

  dst_buff_ = std::make_unique<uint8_t[]>(dst_size_);

  if (aes_.Decrypt(src_buff_.get() + kMagicSize, dst_buff_.get(),
                   src_size_ - kMagicSize, pw_.GetData(), pw_.GetSize())) {
    ReportError(
        "[Auth] Decryption failed - Invalid password or corrupted vault\n");
    return 1;
  }

  /* Deserialize */

  memcpy(&entry_cnt, dst_buff_.get(), kCountSize);
  cur += kCountSize;

  if (entry_cnt * kMinEntrySize > dst_size_ - kCountSize) {
    ReportError(
        "[Data] Validation failed - Entry count exceeds available data\n");
    return 1;
  }

  for (uint32_t i = 0; i < entry_cnt; i++) {
    Entry entry;

    size_t bytes = entry.Deser(dst_buff_.get() + cur, dst_size_ - cur);

    if (bytes == 0) {
      ReportError("[Data] Deserialization failed - Invalid entry data\n");
      return 1;
    }

    cur += bytes;

    tmp.insert(std::move(entry));
  }

  entry_set_ = std::move(tmp);

  Clear();

  return 0;
}

int Vault::SaveVault(const QString& path) {
  size_t src_cur = 0, dst_cur = 0;
  uint32_t entry_cnt = static_cast<uint32_t>(entry_set_.size());

  last_error_.clear();

  /* Calculate vault size */

  src_size_ = sizeof(uint32_t);

  for (auto it = entry_set_.begin(); it != entry_set_.end(); it++) {
    src_size_ += it->Size();
  }

  dst_size_ = kMagicSize + kSaltSize + kIVSize + src_size_ + kTagSize;

  src_buff_ = std::make_unique<uint8_t[]>(src_size_);
  dst_buff_ = std::make_unique<uint8_t[]>(dst_size_);

  /* Write entry count to buffer */

  memcpy(src_buff_.get() + src_cur, &entry_cnt, sizeof(uint32_t));
  src_cur += sizeof(uint32_t);

  /* Write entries to buffer */

  for (auto it = entry_set_.begin(); it != entry_set_.end(); it++) {
    src_cur += it->Ser(src_buff_.get() + src_cur);
  }

  memcpy(dst_buff_.get() + dst_cur, &magic_num_, kMagicSize);
  dst_cur += kMagicSize;

  /* Encrypt */

  if (aes_.Encrypt(src_buff_.get(), dst_buff_.get() + dst_cur, src_size_,
                   pw_.GetData(), pw_.GetSize())) {
    ReportError("[Crypto] Encryption failed - Cannot encrypt vault data\n");
    return 1;
  }

  /* Save to temporary file */

  QString tmp_path = path + ".tmp";

  OpenFile(&file_, tmp_path, "wb");

  if (file_ == nullptr) {
    // LCOV_EXCL_START
    ReportError(
        "[File] Open failed - Cannot open temporary file for writing\n");
    return 1;
    // LCOV_EXCL_STOP
  }

  if (fwrite(dst_buff_.get(), sizeof(uint8_t), dst_size_, file_) != dst_size_) {
    // LCOV_EXCL_START
    ReportError("[File] Write failed - Cannot write temporary file\n");
    RemoveFile(tmp_path);
    return 1;
    // LCOV_EXCL_STOP
  }

  /* Sync file data to disk */

  if (SyncFile(file_)) {
    // LCOV_EXCL_START
    ReportError("[File] Sync failed - Cannot flush vault file to disk\n");
    RemoveFile(tmp_path);
    return 1;
    // LCOV_EXCL_STOP
  }

  fclose(file_);
  file_ = nullptr;

  /* Rename temporary file to vault file */

  if (RenameFile(tmp_path, path)) {
    // LCOV_EXCL_START
    ReportError("[File] Rename failed - Cannot replace vault file\n");
    RemoveFile(tmp_path);
    return 1;
    // LCOV_EXCL_STOP
  }

  Clear();

  return 0;
}

void Vault::CloseVault() {
  entry_set_.clear();
  pw_.Clean();
  Clear();
}

bool Vault::VerifyPW(const Password& cur_pw) const {
  return pw_.Equal(cur_pw);
}

int Vault::ChangePW(const Password& new_pw, const QString& path) {
  last_error_.clear();

  if (pw_.SetData(new_pw)) {
    ReportError(
        "[Auth] Password change failed - Password exceeds maximum length (256 "
        "characters)\n");
    return 1;
  }

  if (SaveVault(path)) {
    return 1;  // LCOV_EXCL_LINE
  }

  return 0;
}

void Vault::SetPW(const Password& pw) {
  pw_ = pw;
}