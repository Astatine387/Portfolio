/**
 * @file	platform_win32.h
 * @brief	Implementation of utility functions for Windows
 * @author	Astatine387
 */

#include <windows.h>

#include <bcrypt.h>
#include <io.h>

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

int GetProcNum() {
  SYSTEM_INFO info;
  GetSystemInfo(&info);
  return static_cast<int>(info.dwNumberOfProcessors);
}

int Random(uint8_t* dst, size_t size) {
  return BCryptGenRandom(NULL, dst, static_cast<ULONG>(size),
                         BCRYPT_USE_SYSTEM_PREFERRED_RNG);
}

int RemoveFile(const std::string& path) {
  std::filesystem::path fs_path = std::filesystem::u8path(path);
  return _wunlink(fs_path.c_str());
}

int RenameFile(const std::string& src, const std::string& dst) {
  std::filesystem::path src_path = std::filesystem::u8path(src);
  std::filesystem::path dst_path = std::filesystem::u8path(dst);

  if (!MoveFileExW(src_path.c_str(), dst_path.c_str(),
                   MOVEFILE_REPLACE_EXISTING)) {
    return 1;  // LCOV_EXCL_LINE
  }

  return 0;
}

int Seek(FILE* file, int64_t offset, int origin) {
  return _fseeki64(file, offset, origin);
}

int SyncFile(FILE* file) {
  if (fflush(file)) {
    return 1;
  }

  HANDLE h = (HANDLE)_get_osfhandle(_fileno(file));

  if (h == INVALID_HANDLE_VALUE) {
    return 1;
  }

  if (!FlushFileBuffers(h)) {
    return 1;
  }

  return 0;
}

void Lock(void* ptr, size_t size) {
  VirtualLock(ptr, size);
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