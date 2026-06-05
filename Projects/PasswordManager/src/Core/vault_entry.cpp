/**
 * @file	vault_entry.cpp
 * @brief	Implementation of entry management functions of Vault class
 * @author	Astatine387
 */

#include "Core/vault.h"

int Vault::CreateEntry(const std::string& site, const std::string& acc, const Password& pw) {
  Entry new_entry = { .site = site, .acc = acc, .pw = pw };

  auto res = entry_set_.insert(new_entry);

  if (!res.second) {
    last_error_ = "[Entry] Insert failed - Entry already exists\n";
    return 1;
  }

  return 0;
}

int Vault::UpdateEntry(const std::string& old_site, const std::string& old_acc, const std::string& new_site,
                       const std::string& new_acc, const Password& new_pw) {
  /* Check whether the target entry exists */

  Entry old_entry = { .site = old_site, .acc = old_acc };

  auto old_it = entry_set_.find(old_entry);

  if (old_it == entry_set_.end()) {
    last_error_ = "[Entry] Update failed - Original entry not found\n";
    return 1;
  }

  /* Check new entry data conflicts with existing entry */

  Entry new_entry = { .site = new_site, .acc = new_acc, .pw = new_pw };

  auto new_it = entry_set_.find(new_entry);

  if (new_it != entry_set_.end() && new_it != old_it) {
    last_error_ = "[Entry] Update failed - Entry already exists\n";
    return 2;
  }

  entry_set_.erase(old_it);

  auto res = entry_set_.insert(new_entry);

  if (!res.second) {
    last_error_ = "[Entry] Update failed - Cannot insert entry\n";
    return 1;
  }

  return 0;
}

int Vault::DeleteEntry(const std::string& site, const std::string& acc) {
  Entry tar = { .site = site, .acc = acc };

  auto it = entry_set_.find(tar);

  if (it == entry_set_.end()) {
    last_error_ = "[Entry] Delete failed - Entry not found\n";
    return 1;
  }

  entry_set_.erase(it);

  return 0;
}