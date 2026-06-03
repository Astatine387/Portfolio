/**
 * @file	platform_win32.cpp
 * @brief	Implementation of utility functions for Windows
 * @author	Astatine387
 */

#include <windows.h>

#include <bcrypt.h>

#include <filesystem>

#include "Utils/platform.h"

int64_t GetFileSize(FILE* file) {
  if (_fseeki64(file, 0, SEEK_END)) {
    return -1;
  }

  int64_t size = _ftelli64(file);
  rewind(file);
  return size;
}

bool FileExists(const std::string& path) {
  std::filesystem::path fs_path = std::filesystem::u8path(path);
  return std::filesystem::exists(fs_path);
}

int Random(uint8_t* dst, size_t size) {
  return BCryptGenRandom(nullptr, dst, static_cast<ULONG>(size), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
}

int RemoveFile(const std::string& path) {
  std::filesystem::path fs_path = std::filesystem::u8path(path);
  return _wunlink(fs_path.c_str());
}

int Seek(FILE* file, int64_t offset, int origin) {
  return _fseeki64(file, offset, origin);
}

int Lock(void* ptr, size_t size) {
  return VirtualLock(ptr, size) ? 0 : 1;
}

void OpenFile(FILE** file, const std::string& path, const char* mode) {
  std::filesystem::path fs_path = std::filesystem::u8path(path);
  std::wstring wmode;

  for (const char* p = mode; *p; ++p) {
    wmode += static_cast<wchar_t>(*p);
  }

  _wfopen_s(file, fs_path.c_str(), wmode.c_str());
}

void Unlock(void* ptr, size_t size) {
  VirtualUnlock(ptr, size);
}

void Wipe(void* ptr, size_t size) {
  SecureZeroMemory(ptr, size);
}