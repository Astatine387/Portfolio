/**
 * @file	vault_file.cpp
 * @brief	Implementation of file management functions of Vault class
 * @author	Astatine387
 */

#include <array>
#include <cstring>
#include <span>

#include "core/vault.h"
#include "utils/platform.h"

namespace {

/**
 * @brief	Read the Argon2id parameter block from a vault header
 * @param	src		Vault file buffer holding at least kKdfParamSize bytes
 * @return	Parameters stored in the header
 */
KdfParams ReadKdfParams(const uint8_t* src) {
  KdfParams params{};

  memcpy(&params.time_cost, src + kMagicSize, sizeof(uint32_t));
  memcpy(&params.mem_cost, src + kMagicSize + sizeof(uint32_t), sizeof(uint32_t));
  memcpy(&params.parallelism, src + kMagicSize + 2 * sizeof(uint32_t), sizeof(uint32_t));

  return params;
}

/**
 * @brief	Write the Argon2id parameter block into a vault header
 * @param	dst			Vault file buffer holding at least kKdfParamSize bytes
 * @param	params		Parameters to store
 */
void WriteKdfParams(uint8_t* dst, const KdfParams& params) {
  memcpy(dst + kMagicSize, &params.time_cost, sizeof(uint32_t));
  memcpy(dst + kMagicSize + sizeof(uint32_t), &params.mem_cost, sizeof(uint32_t));
  memcpy(dst + kMagicSize + 2 * sizeof(uint32_t), &params.parallelism, sizeof(uint32_t));
}

/**
 * @brief	Check whether KDF parameters are within the accepted range
 * @param	params	Parameters read from header
 * @return	kSuccess when every field is in range, kFailure otherwise
 */
Result ValidateKdfParams(const KdfParams& params) {
  if (params.time_cost < kMinTimeCost || params.time_cost > kMaxTimeCost) {
    return Result::kFailure;
  }

  if (params.mem_cost < kMinMemCost || params.mem_cost > kMaxMemCost) {
    return Result::kFailure;
  }

  if (params.parallelism < kMinParallelism || params.parallelism > kMaxParallelism) {
    return Result::kFailure;
  }

  return Result::kSuccess;
}

}  // namespace

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

  memcpy(img_.Data(), &entry_cnt, kCountSize);

  /* Encrypt and write the vault file atomically */

  if (SaveVaultWith(path, *key_, salt_, kdf_) == Result::kFailure) {
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

  /* Check magic number */

  if (memcmp(src_buff_.data(), &magic_num_, kMagicSize) != 0) {
    ReportError("[File] Validation failed - Invalid vault file format\n");
    return Result::kFailure;
  }

  /* Adopt the key-derivation parameters recorded in the header */

  const KdfParams params = ReadKdfParams(src_buff_.data());

  if (ValidateKdfParams(params) == Result::kFailure) {
    ReportError("[File] Validation failed - Invalid vault file format\n");
    return Result::kFailure;
  }

  kdf_ = params;

  /* Read the salt from the header and derive the session key */

  memcpy(salt_.data(), src_buff_.data() + kKdfParamSize, kSaltSize);

  key_ = DeriveKey(std::span<const char>(pw.GetData(), pw.GetSize()), salt_, kdf_);

  if (!key_.has_value()) {
    // LCOV_EXCL_START
    Reset();
    ReportError("[Crypto] Key derivation failed - Argon2id error\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  /* Decrypt into the session image */

  int64_t img_size = src_size_ - static_cast<int64_t>(kKdfParamSize + kSaltSize + kIVSize + kTagSize);

  img_ = SecureBuffer(static_cast<size_t>(img_size));

  if (!img_.Valid()) {
    // LCOV_EXCL_START
    Reset();
    ReportError("[Memory] Allocation failed - Cannot allocate vault image\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  if (aes_.Decrypt(src_buff_.data() + kKdfParamSize, img_.Data(), src_bytes - kKdfParamSize, *key_) ==
      Result::kFailure) {
    Reset();
    ReportError("[Auth] Decryption failed - Invalid password or corrupted vault\n");
    return Result::kFailure;
  }

  /* Deserialize the entries from the image */

  const uint8_t* base = img_.Data();
  size_t img_len = img_.Size();

  memcpy(&entry_cnt, base, kCountSize);
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

  return SaveVaultWith(path, *key_, salt_, kdf_);
}

Result Vault::SaveVaultWith(const std::string& path, const SecureKey& key, std::span<const uint8_t, kSaltSize> salt,
                            const KdfParams& params) {
  /* Verify the image redzone and offset invariant before encrypting */

  if (VerifyImage() == Result::kFailure) {
    return Result::kFailure;  // VerifyImage reported the error
  }

  /* Calculate file size */

  dst_size_ = static_cast<int64_t>(kKdfParamSize + kSaltSize + kIVSize + img_.Size() + kTagSize);

  if (dst_size_ > kMaxSize) {
    // LCOV_EXCL_START
    ReportError("[Data] Validation failed - Vault exceeds maximum size (2 GiB)\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  const size_t dst_bytes = static_cast<size_t>(dst_size_);

  dst_buff_.assign(dst_bytes, 0);

  /* Write the magic number and the parameters the key was derived with */

  memcpy(dst_buff_.data(), &magic_num_, kMagicSize);

  WriteKdfParams(dst_buff_.data(), params);

  /* Encrypt the image; the session salt is written and a fresh IV is generated */

  if (aes_.Encrypt(img_.Data(), dst_buff_.data() + kKdfParamSize, img_.Size(), key, salt) == Result::kFailure) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Encryption failed - Cannot encrypt vault data\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  /* Save to temporary file */

  std::string tmp_path = path + ".tmp";

  OpenFile(&file_, tmp_path, "wb");

  if (file_ == nullptr) {
    ReportError("[File] Open failed - Cannot open temporary file for writing\n");
    return Result::kFailure;
  }

  if (fwrite(dst_buff_.data(), sizeof(uint8_t), dst_bytes, file_) != dst_bytes) {
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

  return key_->ConstantTimeEquals(*cand);
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

  if (SaveVaultWith(path, *new_key, new_salt, new_kdf) == Result::kFailure) {
    return Result::kFailure;  // LCOV_EXCL_LINE
  }

  /* Commit the session state only after the save has succeeded */

  key_ = std::move(new_key);
  salt_ = new_salt;
  kdf_ = new_kdf;

  return Result::kSuccess;
}
