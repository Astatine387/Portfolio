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

/* Both refusals below state the ceiling outright, the way CommitImage's does. A constant moved without the figure
 * beside it moving too would leave the text quietly wrong, so the figure is asserted rather than trusted. */

static_assert(kMaxSize == 4000LL * 1024, "The vault ceiling moved away from the 4,000 KiB these messages state");

Result Vault::NewVault(const std::string& path, const Password& pw) {
  last_error_.clear();

  /* Refuse a path that is already taken, before a password has been typed against it and before the seconds of
   * Argon2id that follow. This is here for whoever is creating the vault, so that the attempt fails at the point the
   * name was chosen rather than after the wait; it is not the guarantee. FileExists answers about the instant it is
   * called, and the derivation below leaves a window in which a sync client or a second instance can take the name,
   * which is why the publish at the end is create-only and decides the same question in the rename itself. */

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

  if (SaveVaultWith(path, *key_, PublishMode::kCreateOnly, SaveMode::kRefuseChanged) != SaveResult::kSuccess) {
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

  /* Resolve the path before it is opened, so that the file this session goes on to claim as its own is named by the
   * file it actually read rather than by a path that may lead somewhere else later. A path that does not resolve is a
   * path nothing can be read from, so it fails here with what the failing open below would have said. */

  std::string real_path;

  if (ResolvePath(path, real_path) == Result::kFailure) {
    ReportError("[File] Open failed - Cannot open vault file\n");
    return Result::kFailure;
  }

  /* Open file pointer */

  OpenFile(&file_, real_path, "rb");

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
    ReportError("[File] Validation failed - File exceeds maximum size (4,000 KiB)\n");
    return Result::kFailure;
  }

  /* Read the header, and nothing else yet. Everything that decides whether this is a vault at all and whether this
   * password opens it lives in these bytes; the body is needed only once both have been answered. Keeping the
   * allocation and the read of up to kMaxSize behind those answers means a wrong magic number never buys them. What
   * a stranger can spend here is these kHeaderSize bytes and the one Argon2id pass Limitations names as the cost a
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

  if (VerifyImage(img_, tmp, ImageOrigin::kFile) == Result::kFailure) {
    Reset();
    return Result::kFailure;  // VerifyImage reported the error
  }

  entry_set_ = std::move(tmp);

  /* Remember which version of the file this session is now holding, taken from the buffer that was decrypted and
   * authenticated a few lines above rather than from a fresh read of the path. src_size_ is at least kMinSize, which
   * accounts for the header and the IV both, so these bytes are there. Clear() wipes the buffer immediately after,
   * which is why this stands ahead of it. */

  RememberFile(path, real_path, std::span<const uint8_t, kIVSize>(src_buff_.data() + kHeaderSize, kIVSize));

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

  /* Recorded whether or not anything is read, because it is half of what is being described: a caller comparing two
   * observations is asking about one file, and two answers about two different files are not comparable. */

  state.file = path;

  OpenFile(&file, path, "rb");

  if (file == nullptr) {
    /* A file that is there but refuses to open still holds the path, and saying otherwise would let the different-
     * path rule replace it. What it cannot do is name a version, so it comes back carrying no IV either way. */

    state.exists = FileExists(path);

    return state;
  }

  state.exists = true;

  /* The IV sits at kHeaderSize, immediately behind the header, and a file too short to reach the end of it is not a
   * version this program wrote. GetFileSize leaves the position at the start of the file, so the seek below is from
   * a known point. */

  constexpr int64_t kIVEnd = static_cast<int64_t>(kHeaderSize + kIVSize);

  std::array<uint8_t, kIVSize> iv{};

  const int64_t size = GetFileSize(file);

  if (size >= kIVEnd && fseek(file, static_cast<long>(kHeaderSize), SEEK_SET) == 0 &&
      fread(iv.data(), sizeof(uint8_t), iv.size(), file) == iv.size()) {
    state.iv = iv;
    state.has_iv = true;
  }

  /* Nothing durable rides on this close: the stream was opened for reading and never written to */

  static_cast<void>(fclose(file));

  return state;
}

void Vault::RememberFile(const std::string& path, const std::string& real_path, std::span<const uint8_t, kIVSize> iv) {
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

  /* The path leads nowhere. If it is the one this session opened or last saved, the file that was behind it is the
   * vault the user means, and the publish recreates it there rather than at the link standing in front of it. */

  if (mark_.has_value() && mark_->path == path) {
    return mark_->real_path;
  }

  return path;
}

SaveResult Vault::CheckTarget(const std::string& path, const std::string& target, SaveMode mode) {
  /* A plain save asks the question afresh, so whatever an earlier conflict was acknowledged for stops standing here.
   * Without this a user could be warned, cancel, edit, save again and have the stale acknowledgement answer for a
   * prompt they never saw. */

  if (mode == SaveMode::kRefuseChanged) {
    ack_.reset();
  }

  const FileState state = ReadFileState(target);

  /* A file other than the one this session read is a changed file in the same sense a changed IV is: what the path
   * leads to now is not what it led to then, and publishing over it would replace a vault nobody has looked at. */

  const bool changed = (mark_.has_value() && mark_->path == path)
                           ? (target != mark_->real_path || !state.has_iv || state.iv != mark_->iv)
                           : state.exists;

  if (!changed) {
    return SaveResult::kSuccess;
  }

  /* An acknowledgement covers the one observation it was given for. The path has to be the same path and the disk
   * has to still show the same thing, or the user would be overwriting a version nobody described to them. */

  if (mode == SaveMode::kOverwriteAcknowledged && ack_.has_value() && ack_->path == path && ack_->state == state) {
    return SaveResult::kSuccess;
  }

  /* Record what was seen before reporting, so the answer to this warning can be checked against it */

  ack_ = Conflict{ .path = path, .state = state };

  ReportError("[File] Save refused - The vault file changed on disk after this session read or wrote it\n");

  return SaveResult::kConflict;
}

SaveResult Vault::SaveVaultWith(const std::string& path, const SecureKey& key, PublishMode mode, SaveMode save) {
  last_warning_.clear();

  /* Confirm the image and the entry set still describe each other before encrypting. The pair checked here is the
   * installed one, which CommitImage has already verified; it is checked again because what is about to be written to
   * disk is these bytes, and a save is the last point at which a disagreement can still be caught instead of
   * stored. */

  if (VerifyImage(img_, entry_set_, ImageOrigin::kSession) == Result::kFailure) {
    return SaveResult::kError;  // VerifyImage reported the error
  }

  /* Calculate file size. Every image that reaches this point is bounded already: NewVault builds a fixed four bytes,
   * OpenVault's came out of a file the kMaxSize check above let through, and CommitImage turns away anything past
   * kMaxImageSize. The exclusion below says unreachable and now means it. The check stays because this is the last
   * point at which an oversized image can be stopped rather than written, and a file past kMaxSize is one OpenVault
   * refuses, which would leave a vault this build wrote and cannot open. */

  dst_size_ = static_cast<int64_t>(kFrameSize + img_.Size());

  if (dst_size_ > kMaxSize) {
    // LCOV_EXCL_START
    ReportError("[Data] Validation failed - Vault exceeds maximum size (4,000 KiB)\n");
    return SaveResult::kError;
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
    return SaveResult::kError;
    // LCOV_EXCL_STOP
  }

  /* Settle which file is being published onto, once, before anything is written. A path leading through a symbolic
   * link does not name the file at the end of it, and the check, the temporary, the rename and the directory flush all
   * have to mean that file: a check that read one file while the rename replaced another would be answering about
   * something nobody was about to overwrite. A create is the one case with nothing to resolve, its whole precondition
   * being that the name holds nothing yet.
   *
   * Once, rather than at each of the four, so that a link repointed while this runs cannot leave them disagreeing. */

  const std::string target = (mode == PublishMode::kReplace) ? ReplaceTarget(path) : path;

  /* Save to a temporary file, in the directory of the file it is going to replace. rename(2) is atomic within one file
   * system and answers EXDEV across two, and a link pointing off to another disk is exactly what puts a vault there,
   * so the temporary follows the target rather than the name that led to it. */

  std::string tmp_path = target + ".XXXXXX";

  if (OpenTempFile(&file_, tmp_path) == Result::kFailure) {
    ReportError("[File] Open failed - Cannot create temporary file for writing\n");
    return SaveResult::kError;
  }

  if (fwrite(dst_buff_.data(), sizeof(uint8_t), dst_bytes, file_) != dst_bytes) {
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

  /* SyncFile above already flushed the stream and fsynced the descriptor, so every byte of the temporary file is on
   * disk before this runs and there is no deferred write left for fclose to report. What it can still return is a
   * close failure, which on Linux releases the descriptor either way and cannot take the data back; the rename below
   * is what publishes the file, and it is checked. */

  static_cast<void>(fclose(file_));
  file_ = nullptr;

  /* Last look at the file before it is taken. This stands here, rather than beside the encryption above, because
   * everything between the two is time a second window or a sync client can write in, and a check is worth only the
   * gap between it and the rename it guards. Nothing durable has happened yet: the bytes are in a temporary of this
   * program's own, so a refusal costs that temporary and nothing else. */

  if (mode == PublishMode::kReplace) {
    const SaveResult check = CheckTarget(path, target, save);

    if (check != SaveResult::kSuccess) {
      RemoveFile(tmp_path);
      return check;  // CheckTarget reported the refusal
    }
  }

  /* Rename the temporary onto the file being published. This is the commit point: the rename is atomic, whatever it
   * does to that file is done the moment it returns, and nothing below can undo it. So nothing below may report the
   * save as anything but a success, since a caller reads kError and kConflict alike as a promise that the file on disk
   * is the one it was before the call.
   *
   * The two modes differ here and nowhere else. kReplace publishes over the vault this session already owns, which is
   * the file the path led to rather than the path itself, so a link standing in front of that vault is left pointing
   * at the new version instead of being replaced by it. kCreateOnly is where a create's precondition is actually
   * decided: the name has to be free at this instant rather than at the instant NewVault looked at it, so the move
   * itself is the test, and a refusal means something took the name while the key was being derived. It is the path
   * as the caller gave it, with nothing resolved away, because a name held by a dangling link is a name that is taken.
   * Either way the temporary is removed on failure, so a refused create leaves the directory as it found it. */

  if (mode == PublishMode::kCreateOnly) {
    const RenameStatus status = RenameFileNoReplace(tmp_path, path);

    if (status != RenameStatus::kOk) {
      RemoveFile(tmp_path);

      if (status == RenameStatus::kExists) {
        ReportError("[File] Create failed - The path was taken before the vault could be written\n");
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

  /* Follow the file that was just published, taking the IV out of the buffer that went to the disk rather than
   * reading the path back: between the rename and a re-read something else could write, and this session would then
   * claim a version it never held. dst_bytes is kFrameSize and up, which covers the header and the IV both. Clear()
   * wipes the buffer immediately after, which is why this stands ahead of it.
   *
   * A publish that resolved the path away knows which file it wrote, that being the one the rename took, and it is
   * taken from there rather than resolved again: a link repointed in the instant after the rename would answer with a
   * file this session never wrote, and the next save would then replace that file unwarned.
   *
   * A publish onto the path itself is the other case, and there the name is resolved instead. It is what a create does
   * always, and what a save does when it publishes onto a name that held nothing; either way the file the name leads
   * to did not exist until the rename made it, so resolving it is what leaves the next save comparing a resolved path
   * against a resolved one rather than against the name it was handed. ResolvePath leaves its output alone when it
   * fails, so a file deleted in the moment between the rename and this leaves the name itself, which the next publish
   * resolves afresh anyway. */

  std::string real_path = target;

  if (target == path) {
    static_cast<void>(ResolvePath(path, real_path));
  }

  RememberFile(path, real_path, std::span<const uint8_t, kIVSize>(dst_buff_.data() + kHeaderSize, kIVSize));

  Clear();

  /* Sync the directory entry so the rename itself survives a crash. Failing here says the vault was published but
   * its directory entry may not outlive a power loss, which is a warning about durability rather than a save that
   * did not happen, and it is reported as one so the session can follow the file that is now on disk. */

  if (SyncDir(target) == Result::kFailure) {
    last_warning_ = "[File] Saved, but the directory entry could not be flushed to disk\n";
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

SaveResult Vault::ChangePW(const Password& pw, const std::string& path, SaveMode mode) {
  last_error_.clear();

  if (!key_.has_value()) {
    ReportError("[Auth] Password change failed - No vault is open\n");
    return SaveResult::kError;
  }

  /* Ask about the file before paying for the derivation. The check before the rename is the one that decides this,
   * and it runs again down there over whatever the disk holds by then; this one is here so that a user whose vault
   * was changed elsewhere is told so now rather than after Argon2id has spent seconds on a save that was never going
   * to be published. */

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

  /* Derive a new key with the current defaults, upgrading a vault written by an older build */

  const KdfParams new_kdf{};

  auto new_key = DeriveKey(std::span<const char>(pw.GetData(), pw.GetSize()), new_salt, new_kdf);

  if (!new_key.has_value()) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Key derivation failed - Argon2id error\n");
    return SaveResult::kError;
    // LCOV_EXCL_STOP
  }

  /* Persist with the new key before changing session state. SaveVaultWith fails only before its rename, so a failure
   * here means the file still belongs to the old key, and a success means it belongs to the new one whether or not
   * the directory entry could be flushed afterwards. The session key follows the file either way. */

  const SaveResult res = SaveVaultWith(path, *new_key, PublishMode::kReplace, mode);

  if (res != SaveResult::kSuccess) {
    return res;
  }

  /* Commit the session state only after the save has succeeded */

  key_ = std::move(new_key);
  salt_ = new_salt;
  kdf_ = new_kdf;

  return SaveResult::kSuccess;
}
