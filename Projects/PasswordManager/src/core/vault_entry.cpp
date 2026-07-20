/**
 * @file	vault_entry.cpp
 * @brief	Implementation of entry management functions of Vault class
 * @author	Astatine387
 */

#include <cstring>

#include "core/vault.h"

size_t Vault::SerializeVault(uint8_t* dst, size_t cur, const std::set<Entry, EntryCmp>::const_iterator& skip) {
  for (auto it = entry_set_.begin(); it != entry_set_.end(); ++it) {
    if (it == skip) {
      continue;
    }

    size_t new_off = cur + sizeof(uint32_t) + it->site.size() + sizeof(uint32_t) + it->acc.size() + sizeof(uint32_t);
    const uint8_t* pw_src = (it->pw_len > 0) ? img_.Data() + it->pw_off : nullptr;

    cur += it->Serialize(dst + cur, pw_src);
    it->pw_off = new_off;
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

  size_t cur = SerializeVault(buff.Data(), kCountSize, entry_set_.end());

  entry.pw_off = cur + sizeof(uint32_t) + entry.site.size() + sizeof(uint32_t) + entry.acc.size() + sizeof(uint32_t);

  const uint8_t* pw_src = (entry.pw_len > 0) ? reinterpret_cast<const uint8_t*>(pw.GetData()) : nullptr;

  entry.Serialize(buff.Data() + cur, pw_src);

  img_ = std::move(buff);
  entry_set_.insert(std::move(entry));

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

  size_t cur = SerializeVault(buff.Data(), kCountSize, old_it);

  entry.pw_off = cur + sizeof(uint32_t) + entry.site.size() + sizeof(uint32_t) + entry.acc.size() + sizeof(uint32_t);

  const uint8_t* pw_src = (entry.pw_len > 0) ? reinterpret_cast<const uint8_t*>(new_pw.GetData()) : nullptr;

  entry.Serialize(buff.Data() + cur, pw_src);

  img_ = std::move(buff);
  entry_set_.erase(old_it);
  entry_set_.insert(std::move(entry));

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

  SerializeVault(nimg.Data(), kCountSize, it);

  img_ = std::move(nimg);
  entry_set_.erase(it);

  return Result::kSuccess;
}
