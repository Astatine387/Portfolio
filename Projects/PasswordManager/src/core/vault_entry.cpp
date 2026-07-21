/**
 * @file	vault_entry.cpp
 * @brief	Implementation of entry management functions of Vault class
 * @author	Astatine387
 */

#include <cstring>
#include <optional>
#include <span>

#include "core/vault.h"

std::optional<size_t> Vault::SerializeVault(SecureBuffer& dst, size_t cur,
                                            const std::set<Entry, EntryCmp>::const_iterator& skip) {
  for (auto it = entry_set_.begin(); it != entry_set_.end(); it++) {
    if (it == skip) {
      continue;
    }

    /* Read the password bytes out of the current image (bounds-checked) */

    auto pw_src = it->PwSpan(img_.Span());

    if (!pw_src.has_value()) {
      // LCOV_EXCL_START
      ReportError("[Data] Serialization failed - Password view falls outside the image\n");
      return std::nullopt;
      // LCOV_EXCL_STOP
    }

    /* Carve the destination subrange for this entry (bounds-checked) */

    auto out = dst.Subspan(cur, it->Size());

    if (!out.has_value()) {
      // LCOV_EXCL_START
      ReportError("[Data] Serialization failed - Destination image too small\n");
      return std::nullopt;
      // LCOV_EXCL_STOP
    }

    size_t written = it->Serialize(*out, *pw_src);

    if (written == 0) {
      return std::nullopt;  // LCOV_EXCL_LINE
    }

    it->pw_off = cur + it->PwOffset();
    cur += written;
  }

  return cur;
}

Result Vault::CreateEntry(const std::string& site, const std::string& acc, const Password& pw) {
  if (entry_set_.contains(Entry{ .site = site, .acc = acc })) {
    last_error_ = "[Entry] Insert failed - Entry already exists\n";
    return Result::kFailure;
  }

  Entry entry{ .site = site, .acc = acc, .pw_len = static_cast<uint32_t>(pw.GetSize()) };

  /* Build a new image containing the existing entries plus the new one */

  size_t total = kCountSize + entry.Size();

  for (const auto& e : entry_set_) {
    total += e.Size();
  }

  SecureBuffer buff(total);

  if (!buff.Valid()) {
    // LCOV_EXCL_START
    ReportError("[Memory] Allocation failed - Cannot allocate vault image\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  uint32_t entry_cnt = static_cast<uint32_t>(entry_set_.size()) + 1;

  memcpy(buff.Data(), &entry_cnt, kCountSize);

  auto cur = SerializeVault(buff, kCountSize, entry_set_.end());

  if (!cur.has_value()) {
    return Result::kFailure;  // SerializeVault reported the error
  }

  /* Append the new entry at the end of the image (bounds-checked) */

  auto out = buff.Subspan(*cur, entry.Size());

  if (!out.has_value()) {
    // LCOV_EXCL_START
    ReportError("[Data] Insert failed - Destination image too small\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  std::span<const uint8_t> pw_src;

  if (entry.pw_len > 0) {
    pw_src = std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(pw.GetData()), entry.pw_len);
  }

  entry.pw_off = *cur + entry.PwOffset();

  if (entry.Serialize(*out, pw_src) == 0) {
    return Result::kFailure;  // LCOV_EXCL_LINE
  }

  img_ = std::move(buff);
  entry_set_.insert(std::move(entry));

  if (VerifyImage() == Result::kFailure) {
    return Result::kFailure;  // VerifyImage reported the error
  }

  return Result::kSuccess;
}

UpdateResult Vault::UpdateEntry(const std::string& old_site, const std::string& old_acc, const std::string& new_site,
                                const std::string& new_acc, const Password& new_pw) {
  /* Check whether the target entry exists */

  auto old_it = entry_set_.find(Entry{ .site = old_site, .acc = old_acc });

  if (old_it == entry_set_.end()) {
    last_error_ = "[Entry] Update failed - Original entry not found\n";
    return UpdateResult::kNotFound;
  }

  /* Check the new entry data does not collide with a different entry */

  auto new_it = entry_set_.find(Entry{ .site = new_site, .acc = new_acc });

  if (new_it != entry_set_.end() && new_it != old_it) {
    last_error_ = "[Entry] Update failed - Entry already exists\n";
    return UpdateResult::kDuplicate;
  }

  Entry entry{ .site = new_site, .acc = new_acc, .pw_len = static_cast<uint32_t>(new_pw.GetSize()) };

  /* Build a new image with the old entry replaced by the updated one */

  size_t total = kCountSize + entry.Size();

  for (const auto& e : entry_set_) {
    total += e.Size();
  }

  total -= old_it->Size();

  SecureBuffer buff(total);

  if (!buff.Valid()) {
    // LCOV_EXCL_START
    ReportError("[Memory] Allocation failed - Cannot allocate vault image\n");
    return UpdateResult::kError;
    // LCOV_EXCL_STOP
  }

  uint32_t entry_cnt = static_cast<uint32_t>(entry_set_.size());

  memcpy(buff.Data(), &entry_cnt, kCountSize);

  auto cur = SerializeVault(buff, kCountSize, old_it);

  if (!cur.has_value()) {
    return UpdateResult::kError;  // SerializeVault reported the error
  }

  /* Append the updated entry at the end of the image (bounds-checked) */

  auto out = buff.Subspan(*cur, entry.Size());

  if (!out.has_value()) {
    // LCOV_EXCL_START
    ReportError("[Data] Update failed - Destination image too small\n");
    return UpdateResult::kError;
    // LCOV_EXCL_STOP
  }

  std::span<const uint8_t> pw_src;

  if (entry.pw_len > 0) {
    pw_src = std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(new_pw.GetData()), entry.pw_len);
  }

  entry.pw_off = *cur + entry.PwOffset();

  if (entry.Serialize(*out, pw_src) == 0) {
    return UpdateResult::kError;  // LCOV_EXCL_LINE
  }

  img_ = std::move(buff);
  entry_set_.erase(old_it);
  entry_set_.insert(std::move(entry));

  if (VerifyImage() == Result::kFailure) {
    return UpdateResult::kError;  // VerifyImage reported the error
  }

  return UpdateResult::kSuccess;
}

Result Vault::DeleteEntry(const std::string& site, const std::string& acc) {
  auto it = entry_set_.find(Entry{ .site = site, .acc = acc });

  if (it == entry_set_.end()) {
    last_error_ = "[Entry] Delete failed - Entry not found\n";
    return Result::kFailure;
  }

  /* Build a new image without the target entry */

  size_t total = kCountSize;

  for (const auto& e : entry_set_) {
    total += e.Size();
  }

  total -= it->Size();

  SecureBuffer nimg(total);

  if (!nimg.Valid()) {
    // LCOV_EXCL_START
    ReportError("[Memory] Allocation failed - Cannot allocate vault image\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  uint32_t entry_cnt = static_cast<uint32_t>(entry_set_.size()) - 1;

  memcpy(nimg.Data(), &entry_cnt, kCountSize);

  if (!SerializeVault(nimg, kCountSize, it).has_value()) {
    return Result::kFailure;  // SerializeVault reported the error
  }

  img_ = std::move(nimg);
  entry_set_.erase(it);

  if (VerifyImage() == Result::kFailure) {
    return Result::kFailure;  // VerifyImage reported the error
  }

  return Result::kSuccess;
}

Result Vault::VerifyImage() {
  /* The trailing redzone must be intact after the last image mutation */

  if (!img_.RedzoneIntact()) {
    // LCOV_EXCL_START
    ReportError("[Memory] Integrity check failed - Image redzone was overwritten\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  /* Re-parse the image and confirm the recorded offsets match a fresh parse */

  std::span<const uint8_t> img = img_.Span();

  uint32_t entry_cnt = 0;

  memcpy(&entry_cnt, img.data(), kCountSize);

  if (entry_cnt != entry_set_.size()) {
    // LCOV_EXCL_START
    ReportError("[Data] Integrity check failed - Image entry count mismatch\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  size_t cur = kCountSize;

  for (uint32_t i = 0; i < entry_cnt; i++) {
    Entry parsed;

    size_t bytes = parsed.Deserialize(img.data() + cur, img.size() - cur, cur);

    if (bytes == 0) {
      // LCOV_EXCL_START
      ReportError("[Data] Integrity check failed - Invalid entry data in image\n");
      return Result::kFailure;
      // LCOV_EXCL_STOP
    }

    auto match = entry_set_.find(parsed);

    if (match == entry_set_.end() || match->pw_off != parsed.pw_off || match->pw_len != parsed.pw_len) {
      // LCOV_EXCL_START
      ReportError("[Data] Integrity check failed - Entry offset invariant violated\n");
      return Result::kFailure;
      // LCOV_EXCL_STOP
    }

    cur += bytes;
  }

  if (cur != img.size()) {
    // LCOV_EXCL_START
    ReportError("[Data] Integrity check failed - Trailing bytes after final entry\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  return Result::kSuccess;
}
