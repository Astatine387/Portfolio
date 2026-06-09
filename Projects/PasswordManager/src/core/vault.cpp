/**
 * @file	vault.cpp
 * @brief	Implementation of basic functions of Vault class
 * @author	Astatine387
 */

#include "core/vault.h"

#include "utils/platform.h"

Vault::Vault() {
  aes_.SetErrorCallback([this](const char* msg) { last_error_ = msg; });
}

Vault::~Vault() {
  Clear();
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

void Vault::Clear() {
  if (file_) {
    fclose(file_);
    file_ = nullptr;
  }

  if (!src_buff_.empty()) {
    Wipe(src_buff_.data(), src_buff_.size());
    src_buff_.clear();
  }

  if (!dst_buff_.empty()) {
    Wipe(dst_buff_.data(), dst_buff_.size());
    dst_buff_.clear();
  }

  src_size_ = 0;
  dst_size_ = 0;
}

void Vault::ReportError(const char* msg) {
  last_error_ = msg;

  if (ecb_) {
    ecb_(last_error_.c_str());
  }

  Clear();
}