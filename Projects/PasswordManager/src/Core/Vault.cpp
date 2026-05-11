/**
 * @file	Vault.cpp
 * @brief	Implementation of basic functions Vault class
 * @author	Astatine387
 */

#include "Core/Vault.h"

#include "Utils/library.h"

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

  if (src_buff_) {
    Wipe(src_buff_.get(), src_size_);
    src_buff_.reset();
  }

  if (dst_buff_) {
    Wipe(dst_buff_.get(), dst_size_);
    dst_buff_.reset();
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