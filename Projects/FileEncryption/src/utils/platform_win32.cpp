/**
 * @file	platform_win32.cpp
 * @brief	Implementation of utility functions for Windows
 * @author	Astatine387
 */

#include <windows.h>

#include <bcrypt.h>

#include <filesystem>

#include "utils/platform.h"

int64_t GetFileSize(FILE* file) {
  if (_fseeki64(file, 0, SEEK_END)) {
    return -1;
  }

  int64_t size = _ftelli64(file);

  if (_fseeki64(file, 0, SEEK_SET)) {
    return -1;
  }

  return size;
}

bool FileExists(const std::string& path) {
  std::filesystem::path fs_path(std::u8string(path.begin(), path.end()));
  return std::filesystem::exists(fs_path);
}

Result Random(uint8_t* dst, size_t size) {
  if (BCryptGenRandom(nullptr, dst, static_cast<ULONG>(size), BCRYPT_USE_SYSTEM_PREFERRED_RNG)) {
    return Result::kFailure;  // LCOV_EXCL_LINE
  }

  return Result::kSuccess;
}

Result RemoveFile(const std::string& path) {
  std::filesystem::path fs_path(std::u8string(path.begin(), path.end()));

  if (_wunlink(fs_path.c_str())) {
    return Result::kFailure;
  }

  return Result::kSuccess;
}

Result Seek(FILE* file, int64_t offset, int origin) {
  if (_fseeki64(file, offset, origin)) {
    return Result::kFailure;
  }

  return Result::kSuccess;
}

void OpenFile(FILE** file, const std::string& path, const char* mode) {
  std::filesystem::path fs_path(std::u8string(path.begin(), path.end()));

  std::wstring wmode;

  for (const char* p = mode; *p; ++p) {
    wmode += static_cast<wchar_t>(*p);
  }

  _wfopen_s(file, fs_path.c_str(), wmode.c_str());
}