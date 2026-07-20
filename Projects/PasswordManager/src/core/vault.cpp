/**
 * @file	vault.cpp
 * @brief	Implementation of basic functions of Vault class
 * @author	Astatine387
 */

#include "core/vault.h"

#include <sodium.h>

Vault::Vault() {
  aes_.SetErrorCallback([this](const char* msg) { last_error_ = msg; });
}

Vault::~Vault() {
  CloseVault();
}

const std::set<Entry, EntryCmp>& Vault::GetEntries() const {
  return entry_set_;
}

const std::string& Vault::GetLastError() const {
  return last_error_;
}

int Vault::GetEntryCount() const {
  return static_cast<int>(entry_set_.size());
}

bool Vault::GetEntryPW(const std::string& site, const std::string& acc, Password& dst) const {
  auto it = entry_set_.find(Entry{ .site = site, .acc = acc });

  if (it == entry_set_.end()) {
    return false;
  }

  const char* pw_ptr = (it->pw_len > 0) ? reinterpret_cast<const char*>(img_.Data() + it->pw_off) : nullptr;

  return dst.SetData(pw_ptr, it->pw_len) == Result::kSuccess;
}

void Vault::Clear() {
  if (file_) {
    fclose(file_);
    file_ = nullptr;
  }

  if (!src_buff_.empty()) {
    sodium_memzero(src_buff_.data(), src_buff_.size());
    src_buff_.clear();
  }

  if (!dst_buff_.empty()) {
    sodium_memzero(dst_buff_.data(), dst_buff_.size());
    dst_buff_.clear();
  }

  src_size_ = 0;
  dst_size_ = 0;
}

void Vault::Reset() {
  entry_set_.clear();
  img_.Reset();
  key_.reset();
  sodium_memzero(salt_.data(), salt_.size());
}

void Vault::ReportError(const char* msg) {
  last_error_ = msg;

  if (ecb_) {
    ecb_(last_error_.c_str());
  }

  Clear();
}
