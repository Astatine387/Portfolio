/**
 * @file	vault_entry.cpp
 * @brief	Implementation of entry management functions of Vault class
 * @author	Astatine387
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

/* The messages state their ceiling outright, the way the dialog's already do. A constant moved without the figure
 * beside it moving too would leave the text quietly wrong, so the figure is asserted rather than trusted. */

static_assert(kMaxSiteLen == 256 && kMaxAccLen == 256 && kMaxEntryPwLen == 256,
              "A field ceiling moved away from the 256 bytes these messages state");

/* Same for the vault ceiling, which CommitImage below and SaveVaultWith both state in figures */

static_assert(kMaxSize == 4LL * 1024 * 1024, "The vault ceiling moved away from the 4 MiB these messages state");

/**
 * @brief   Check entry fields against what the on-disk format accepts
 * @param   site    Site name of the entry
 * @param   acc     Account of the entry
 * @param   pw      Password of the entry
 * @return  Reason the fields were refused, or nullptr when every one of them fits
 *
 * Entry::Deserialize refuses a site or account past its ceiling and a password past kMaxEntryPwLen, so an image
 * built out of longer fields is one the parser that wrote it cannot read back. The only check on the way in used to
 * stand in EntryGUI::OnOKClicked, a layer the tests do not reach and one that a second entry point would not go
 * through, which left the format's own invariant resting on the dialog. It rests here now.
 */
const char* ValidateEntryFields(const std::string& site, const std::string& acc, const Password& pw) {
  if (site.empty()) {
    return "[Entry] Validation failed - Site name is empty\n";
  }

  if (site.size() > static_cast<size_t>(kMaxSiteLen)) {
    return "[Entry] Validation failed - Site name exceeds maximum size (256 bytes)\n";
  }

  if (acc.empty()) {
    return "[Entry] Validation failed - Account is empty\n";
  }

  if (acc.size() > static_cast<size_t>(kMaxAccLen)) {
    return "[Entry] Validation failed - Account exceeds maximum size (256 bytes)\n";
  }

  /* kMinEntrySize assumes each of the three fields carries at least one byte, and OpenVault sizes its entry-count
   * check on that figure. This is where the assumption is made true: without it a vault this build writes is one
   * this build refuses to open. */

  if (pw.IsEmpty()) {
    return "[Entry] Validation failed - Password is empty\n";
  }

  /* Password refuses more than kMaxMasterPwLen, so it cannot carry more than kMaxEntryPwLen while the static_assert
   * in constants.h holds; kept because that assert binds the two ceilings in one direction only, and a kMaxEntryPwLen
   * set below kMaxMasterPwLen would make this the one check standing between a long password and a vault that cannot
   * read itself back */

  if (pw.GetSize() > static_cast<size_t>(kMaxEntryPwLen)) {
    return "[Entry] Validation failed - Password exceeds maximum size (256 bytes)\n";  // LCOV_EXCL_LINE
  }

  return nullptr;
}

}  // namespace

std::optional<size_t> Vault::SerializeVault(SecureBuffer& dst, size_t cur, std::set<Entry, EntryCmp>& out_entries,
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
      return std::nullopt;  // LCOV_EXCL_LINE; the two checks above are exactly Serialize's own refusals
    }

    /* Record where the bytes landed in dst, on a copy. The live entry still describes img_, and it goes on doing so
     * whether or not this rebuild is ever installed. */

    Entry rewritten = *it;

    rewritten.pw_off = cur + rewritten.PwOffset();
    out_entries.insert(std::move(rewritten));

    cur += written;
  }

  return cur;
}

Result Vault::CommitImage(SecureBuffer&& img, std::set<Entry, EntryCmp>&& entries) {
  /* The ceiling is read here rather than in each operation that rebuilds an image. This is the only place img_ is
   * written while a vault is open, so an operation added later cannot walk around the check by forgetting it, which is
   * what a copy of it standing in CreateEntry and UpdateEntry would have invited.
   *
   * Refusing at the entry that does not fit, rather than at the save that will not go through, is the point. The check
   * SaveVaultWith makes stays where it is and is now a backstop; before this, it was the only guard, and it left a user
   * holding a session whose only route out was deleting entries it would not name. */

  if (img.Size() > static_cast<size_t>(kMaxImageSize)) {
    ReportError("[Data] Commit failed - Vault would exceed maximum size (4 MiB)\n");
    return Result::kFailure;
  }

  if (VerifyImage(img, entries) == Result::kFailure) {
    /* Unreachable from the CRUD paths as they stand, and the reason to keep it is that it is what makes them safe to
     * get wrong: a rebuild that does not describe itself correctly is dropped here rather than installed */

    return Result::kFailure;  // LCOV_EXCL_LINE; VerifyImage reported the error
  }

  img_ = std::move(img);
  entry_set_ = std::move(entries);
  dirty_ = true;

  return Result::kSuccess;
}

Result Vault::CreateEntry(const std::string& site, const std::string& acc, const Password& pw) {
  const char* invalid = ValidateEntryFields(site, acc, pw);

  if (invalid != nullptr) {
    ReportError(invalid);
    return Result::kFailure;
  }

  if (entry_set_.contains(Entry{ .site = site, .acc = acc })) {
    ReportError("[Entry] Insert failed - Entry already exists\n");
    return Result::kFailure;
  }

  Entry entry{ .site = site, .acc = acc, .pw_len = static_cast<uint32_t>(pw.GetSize()) };

  /* Build a candidate image containing the existing entries plus the new one. Nothing below touches img_ or
   * entry_set_; every return before CommitImage leaves the session exactly as it was found. */

  size_t total = kCountSize + entry.Size();

  for (const auto& e : entry_set_) {
    total += e.Size();
  }

  SecureBuffer buff(total);

  if (!buff.Valid()) {
    /* sodium_malloc refusing the allocation; still checked because Data() would otherwise be a null pointer written
     * through on the next line */

    // LCOV_EXCL_START
    ReportError("[Memory] Allocation failed - Cannot allocate vault image\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  uint32_t entry_cnt = static_cast<uint32_t>(entry_set_.size()) + 1;

  StoreLE32(buff.Data(), entry_cnt);

  std::set<Entry, EntryCmp> candidate;

  auto cur = SerializeVault(buff, kCountSize, candidate, entry_set_.end());

  if (!cur.has_value()) {
    return Result::kFailure;  // LCOV_EXCL_LINE; SerializeVault reported the error
  }

  /* Append the new entry at the end of the candidate image (bounds-checked) */

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
    return Result::kFailure;  // LCOV_EXCL_LINE; the Subspan check above is Serialize's own size refusal
  }

  candidate.insert(std::move(entry));

  return CommitImage(std::move(buff), std::move(candidate));
}

UpdateResult Vault::UpdateEntry(const std::string& old_site, const std::string& old_acc, const std::string& new_site,
                                const std::string& new_acc, const Password& new_pw) {
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

  Entry entry{ .site = new_site, .acc = new_acc, .pw_len = static_cast<uint32_t>(new_pw.GetSize()) };

  /* Build a candidate image with the old entry replaced by the updated one. old_it stays valid throughout, since the
   * set it points into is only read from here on. */

  size_t total = kCountSize + entry.Size();

  for (const auto& e : entry_set_) {
    total += e.Size();
  }

  total -= old_it->Size();

  SecureBuffer buff(total);

  if (!buff.Valid()) {
    /* sodium_malloc refusing the allocation; still checked because Data() would otherwise be a null pointer written
     * through on the next line */

    // LCOV_EXCL_START
    ReportError("[Memory] Allocation failed - Cannot allocate vault image\n");
    return UpdateResult::kError;
    // LCOV_EXCL_STOP
  }

  uint32_t entry_cnt = static_cast<uint32_t>(entry_set_.size());

  StoreLE32(buff.Data(), entry_cnt);

  std::set<Entry, EntryCmp> candidate;

  auto cur = SerializeVault(buff, kCountSize, candidate, old_it);

  if (!cur.has_value()) {
    return UpdateResult::kError;  // LCOV_EXCL_LINE; SerializeVault reported the error
  }

  /* Append the updated entry at the end of the candidate image (bounds-checked) */

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
    return UpdateResult::kError;  // LCOV_EXCL_LINE; the Subspan check above is Serialize's own size refusal
  }

  candidate.insert(std::move(entry));

  /* The old entry was never inserted into the candidate set, so installing it is the whole of the replacement. The
   * failure below is reachable: an update that grows an entry can be the one that carries the image past kMaxImageSize,
   * which is why it no longer claims otherwise. */

  if (CommitImage(std::move(buff), std::move(candidate)) == Result::kFailure) {
    return UpdateResult::kError;  // CommitImage reported the error and installed nothing
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

  for (const auto& e : entry_set_) {
    total += e.Size();
  }

  total -= it->Size();

  SecureBuffer nimg(total);

  if (!nimg.Valid()) {
    /* sodium_malloc refusing the allocation; still checked because Data() would otherwise be a null pointer written
     * through on the next line */

    // LCOV_EXCL_START
    ReportError("[Memory] Allocation failed - Cannot allocate vault image\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  uint32_t entry_cnt = static_cast<uint32_t>(entry_set_.size()) - 1;

  StoreLE32(nimg.Data(), entry_cnt);

  std::set<Entry, EntryCmp> candidate;

  if (!SerializeVault(nimg, kCountSize, candidate, it).has_value()) {
    return Result::kFailure;  // LCOV_EXCL_LINE; SerializeVault reported the error
  }

  /* Skipping the target is the deletion: the candidate set is built without it rather than erased from */

  return CommitImage(std::move(nimg), std::move(candidate));
}

Result Vault::VerifyImage(const SecureBuffer& img, const std::set<Entry, EntryCmp>& entries) {
  /* Re-parse the image and confirm the recorded offsets match a fresh parse. Every branch below is defensive and
   * none of them is reached by a run of the suite; what changed is the cost of being wrong about that. A caller now
   * hands over a candidate it has not installed, so a failure here is a rebuild discarded rather than a session left
   * holding an image its entries no longer describe. Each refusal is kept for the case it was written against. */

  std::span<const uint8_t> view = img.Span();

  if (view.size() < kCountSize) {
    // LCOV_EXCL_START
    ReportError("[Data] Integrity check failed - Image too small for the entry count\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  uint32_t entry_cnt = LoadLE32(view.data());

  if (entry_cnt != entries.size()) {
    // LCOV_EXCL_START
    ReportError("[Data] Integrity check failed - Image entry count mismatch\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  size_t cur = kCountSize;

  for (uint32_t i = 0; i < entry_cnt; i++) {
    Entry parsed;

    size_t bytes = parsed.Deserialize(view.data() + cur, view.size() - cur, cur);

    if (bytes == 0) {
      // LCOV_EXCL_START
      ReportError("[Data] Integrity check failed - Invalid entry data in image\n");
      return Result::kFailure;
      // LCOV_EXCL_STOP
    }

    auto match = entries.find(parsed);

    if (match == entries.end() || match->pw_off != parsed.pw_off || match->pw_len != parsed.pw_len) {
      // LCOV_EXCL_START
      ReportError("[Data] Integrity check failed - Entry offset invariant violated\n");
      return Result::kFailure;
      // LCOV_EXCL_STOP
    }

    cur += bytes;
  }

  if (cur != view.size()) {
    // LCOV_EXCL_START
    ReportError("[Data] Integrity check failed - Trailing bytes after final entry\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  return Result::kSuccess;
}
