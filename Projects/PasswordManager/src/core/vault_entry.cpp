/**
 * @file    vault_entry.cpp
 * @brief   Implementation of entry management functions of Vault class
 * @author  Astatine387
 */

#include <cstddef>
#include <optional>
#include <span>
#include <string>

#include "common/constants.h"
#include "core/vault.h"
#include "utils/byte_order.h"
#include "utils/password.h"

namespace {

static_assert(
    kMaxSiteLen == 256 && kMaxAccLen == 256 && kMaxEntryPwLen == 256,
    "A field ceiling moved away from the 256 bytes these messages state");

static_assert(
    kMaxSize == 4000LL * 1024,
    "The vault ceiling moved away from the 4,000 KiB these messages state");

/**
 * @brief   Check entry fields against what the on-disk format accepts
 * @param   site  Site name of the entry
 * @param   acc   Account of the entry
 * @param   pw    Password of the entry
 * @return  Reason the fields were refused, or nullptr when every fields fit
 */
const char* ValidateEntryFields(const std::string& site, const std::string& acc,
                                const Password& pw) {
  if (site.empty()) {
    return "[Entry] Validation failed - Site name is empty\n";
  }

  if (site.size() > static_cast<size_t>(kMaxSiteLen)) {
    return "[Entry] Validation failed - Site name exceeds maximum size (256 "
           "bytes)\n";
  }

  if (acc.empty()) {
    return "[Entry] Validation failed - Account is empty\n";
  }

  if (acc.size() > static_cast<size_t>(kMaxAccLen)) {
    return "[Entry] Validation failed - Account exceeds maximum size (256 "
           "bytes)\n";
  }

  if (pw.IsEmpty()) {
    return "[Entry] Validation failed - Password is empty\n";
  }

  if (pw.GetSize() > static_cast<size_t>(kMaxEntryPwLen)) {
    return "[Entry] Validation failed - Password exceeds maximum size (256 "
           "bytes)\n";  // LCOV_EXCL_LINE
  }

  return nullptr;
}

}  // namespace

std::optional<size_t> Vault::SerializeVault(
    SecureBuffer& src, size_t cur, std::set<Entry, EntryCmp>& dst,
    const std::set<Entry, EntryCmp>::const_iterator& skip) {
  for (auto it = entry_set_.begin(); it != entry_set_.end(); it++) {
    if (it == skip) {
      continue;
    }

    /* Read the password bytes out of the current image (bounds-checked) */

    auto pw = it->PwSpan(img_.Span());

    if (!pw.has_value()) {
      // LCOV_EXCL_START
      ReportError(
          "[Data] Serialization failed - Password view falls outside the "
          "image\n");
      return std::nullopt;
      // LCOV_EXCL_STOP
    }

    /* Carve the destination subrange for this entry (bounds-checked) */

    auto img = src.Subspan(cur, it->Size());

    if (!img.has_value()) {
      // LCOV_EXCL_START
      ReportError(
          "[Data] Serialization failed - Destination image too small\n");
      return std::nullopt;
      // LCOV_EXCL_STOP
    }

    size_t written = it->Serialize(*img, *pw);

    if (written == 0) {
      return std::nullopt;  // LCOV_EXCL_LINE
    }

    /* Record where the bytes landed in dst, on a copy */

    Entry rewritten = *it;

    rewritten.pw_off = cur + rewritten.PwOffset();
    dst.insert(std::move(rewritten));

    cur += written;
  }

  return cur;
}

Result Vault::CommitImage(SecureBuffer&& img,
                          std::set<Entry, EntryCmp>&& entries) {
  if (img.Size() > static_cast<size_t>(kMaxImageSize)) {
    ReportError(
        "[Data] Commit failed - Vault would exceed maximum size (4,000 KiB)\n");
    return Result::kFailure;
  }

  if (VerifyImage(img, entries, ImageOrigin::kSession) == Result::kFailure) {
    return Result::kFailure;  // LCOV_EXCL_LINE
  }

  img_ = std::move(img);
  entry_set_ = std::move(entries);
  dirty_ = true;

  return Result::kSuccess;
}

Result Vault::CreateEntry(const std::string& site, const std::string& acc,
                          const Password& pw) {
  const char* invalid = ValidateEntryFields(site, acc, pw);

  if (invalid != nullptr) {
    ReportError(invalid);
    return Result::kFailure;
  }

  if (entry_set_.contains(Entry{ .site = site, .acc = acc })) {
    ReportError("[Entry] Insert failed - Entry already exists\n");
    return Result::kFailure;
  }

  Entry new_entry{ .site = site,
                   .acc = acc,
                   .pw_len = static_cast<uint32_t>(pw.GetSize()) };

  /* Build a candidate image containing the existing entries plus the new one */

  size_t total = kCountSize + new_entry.Size();

  for (const auto& entry : entry_set_) {
    total += entry.Size();
  }

  SecureBuffer buff(total);

  if (!buff.Valid()) {
    // LCOV_EXCL_START
    ReportError("[Memory] Allocation failed - Cannot allocate vault image\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  uint32_t entry_cnt = static_cast<uint32_t>(entry_set_.size()) + 1;

  StoreLE32(buff.Data(), entry_cnt);

  std::set<Entry, EntryCmp> tmp;

  auto cur = SerializeVault(buff, kCountSize, tmp, entry_set_.end());

  if (!cur.has_value()) {
    return Result::kFailure;  // LCOV_EXCL_LINE
  }

  /* Append the new entry at the end of the candidate image (bounds-checked) */

  auto out = buff.Subspan(*cur, new_entry.Size());

  if (!out.has_value()) {
    // LCOV_EXCL_START
    ReportError("[Data] Insert failed - Destination image too small\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  std::span<const uint8_t> pw_src;

  if (new_entry.pw_len > 0) {
    pw_src = std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(pw.GetData()), new_entry.pw_len);
  }

  new_entry.pw_off = *cur + new_entry.PwOffset();

  if (new_entry.Serialize(*out, pw_src) == 0) {
    return Result::kFailure;  // LCOV_EXCL_LINE
  }

  tmp.insert(std::move(new_entry));

  return CommitImage(std::move(buff), std::move(tmp));
}

UpdateResult Vault::UpdateEntry(const std::string& old_site,
                                const std::string& old_acc,
                                const std::string& new_site,
                                const std::string& new_acc,
                                const Password& new_pw) {
  const char* invalid = ValidateEntryFields(new_site, new_acc, new_pw);

  if (invalid != nullptr) {
    ReportError(invalid);
    return UpdateResult::kError;
  }

  /* Check whether the target entry exists */

  auto old_it = entry_set_.find(Entry{ .site = old_site, .acc = old_acc });

  if (old_it == entry_set_.end()) {
    ReportError("[Entry] Update failed - Original entry not found\n");
    return UpdateResult::kNotFound;
  }

  /* Check the new entry data does not collide with a different entry */

  auto new_it = entry_set_.find(Entry{ .site = new_site, .acc = new_acc });

  if (new_it != entry_set_.end() && new_it != old_it) {
    ReportError("[Entry] Update failed - Entry already exists\n");
    return UpdateResult::kDuplicate;
  }

  Entry new_entry{ .site = new_site,
                   .acc = new_acc,
                   .pw_len = static_cast<uint32_t>(new_pw.GetSize()) };

  size_t total = kCountSize + new_entry.Size();

  for (const auto& entry : entry_set_) {
    total += entry.Size();
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

  StoreLE32(buff.Data(), entry_cnt);

  std::set<Entry, EntryCmp> tmp;

  auto cur = SerializeVault(buff, kCountSize, tmp, old_it);

  if (!cur.has_value()) {
    return UpdateResult::kError;  // LCOV_EXCL_LINE
  }

  /* Append the new entry at the end of the candidate image (bounds-checked) */

  auto out = buff.Subspan(*cur, new_entry.Size());

  if (!out.has_value()) {
    // LCOV_EXCL_START
    ReportError("[Data] Update failed - Destination image too small\n");
    return UpdateResult::kError;
    // LCOV_EXCL_STOP
  }

  std::span<const uint8_t> pw_src;

  if (new_entry.pw_len > 0) {
    pw_src = std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(new_pw.GetData()), new_entry.pw_len);
  }

  new_entry.pw_off = *cur + new_entry.PwOffset();

  if (new_entry.Serialize(*out, pw_src) == 0) {
    return UpdateResult::kError;  // LCOV_EXCL_LINE
  }

  tmp.insert(std::move(new_entry));

  if (CommitImage(std::move(buff), std::move(tmp)) == Result::kFailure) {
    return UpdateResult::kError;
  }

  return UpdateResult::kSuccess;
}

Result Vault::DeleteEntry(const std::string& site, const std::string& acc) {
  auto it = entry_set_.find(Entry{ .site = site, .acc = acc });

  if (it == entry_set_.end()) {
    ReportError("[Entry] Delete failed - Entry not found\n");
    return Result::kFailure;
  }

  /* Build a candidate image without the target entry */

  size_t total = kCountSize;

  for (const auto& entry : entry_set_) {
    total += entry.Size();
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

  StoreLE32(nimg.Data(), entry_cnt);

  std::set<Entry, EntryCmp> tmp;

  if (!SerializeVault(nimg, kCountSize, tmp, it).has_value()) {
    return Result::kFailure;  // LCOV_EXCL_LINE
  }

  /* Skipping the target is the deletion: build the candidate set without it */

  return CommitImage(std::move(nimg), std::move(tmp));
}

Result Vault::VerifyImage(const SecureBuffer& img,
                          const std::set<Entry, EntryCmp>& entries,
                          ImageOrigin origin) {
  auto report = [this, origin](const char* detail) {
    std::string msg = (origin == ImageOrigin::kFile)
                          ? "[Data] Validation failed - "
                          : "[Data] Integrity check failed - ";

    msg += detail;
    msg += '\n';

    ReportError(msg.c_str());
  };

  std::span<const uint8_t> view = img.Span();

  if (view.size() < kCountSize) {
    // LCOV_EXCL_START
    report("Image too small for the entry count");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  uint32_t entry_cnt = LoadLE32(view.data());

  if (entry_cnt != entries.size()) {
    // LCOV_EXCL_START
    report("Image entry count mismatch");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  size_t cur = kCountSize;

  for (uint32_t i = 0; i < entry_cnt; i++) {
    Entry parsed;

    size_t bytes =
        parsed.Deserialize(view.data() + cur, view.size() - cur, cur);

    if (bytes == 0) {
      // LCOV_EXCL_START
      report("Invalid entry data in image");
      return Result::kFailure;
      // LCOV_EXCL_STOP
    }

    auto match = entries.find(parsed);

    if (match == entries.end() || match->pw_off != parsed.pw_off ||
        match->pw_len != parsed.pw_len) {
      // LCOV_EXCL_START
      report("Entry offset invariant violated");
      return Result::kFailure;
      // LCOV_EXCL_STOP
    }

    cur += bytes;
  }

  if (cur != view.size()) {
    report("Trailing bytes after final entry");
    return Result::kFailure;
  }

  return Result::kSuccess;
}
