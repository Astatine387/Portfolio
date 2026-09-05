/**
 * @file	platform_win32.cpp
 * @brief	Implementation of utility functions for Windows
 * @author	Astatine387
 */

#include <windows.h>

#include <bcrypt.h>
#include <fcntl.h>
#include <io.h>

#include <filesystem>

#include "utils/platform.h"

namespace {

std::filesystem::path ToPath(const std::string& path) {
  return std::filesystem::path(std::u8string(reinterpret_cast<const char8_t*>(path.data()), path.size()));
}

}  // namespace

bool FileExists(const std::string& path) {
  std::filesystem::path fs_path = ToPath(path);
  return std::filesystem::exists(fs_path);
}

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

Result Random(uint8_t* dst, size_t size) {
  if (BCryptGenRandom(nullptr, dst, static_cast<ULONG>(size), BCRYPT_USE_SYSTEM_PREFERRED_RNG)) {
    return Result::kFailure;  // LCOV_EXCL_LINE
  }

  return Result::kSuccess;
}

Result RemoveFile(const std::string& path) {
  std::filesystem::path fs_path = ToPath(path);

  if (_wunlink(fs_path.c_str())) {
    return Result::kFailure;
  }

  return Result::kSuccess;
}

Result RenameFile(const std::string& src, const std::string& dst) {
  std::filesystem::path src_path = ToPath(src);
  std::filesystem::path dst_path = ToPath(dst);

  if (!MoveFileExW(src_path.c_str(), dst_path.c_str(), MOVEFILE_WRITE_THROUGH)) {
    return Result::kFailure;
  }

  return Result::kSuccess;
}

Result SyncFile(FILE* file) {
  if (fflush(file)) {
    return Result::kFailure;
  }

  const intptr_t ptr = _get_osfhandle(_fileno(file));

  HANDLE handle = reinterpret_cast<HANDLE>(ptr);  // NOLINT(performance-no-int-to-ptr)

  if (handle == INVALID_HANDLE_VALUE) {
    return Result::kFailure;
  }

  if (!FlushFileBuffers(handle)) {
    return Result::kFailure;
  }

  return Result::kSuccess;
}

Result SyncDir([[maybe_unused]] const std::string& path) {
  return Result::kSuccess;
}

Result Seek(FILE* file, int64_t offset, int origin) {
  if (_fseeki64(file, offset, origin)) {
    return Result::kFailure;
  }

  return Result::kSuccess;
}

void OpenFile(FILE** file, const std::string& path, const char* mode) {
  std::filesystem::path fs_path = ToPath(path);
  std::wstring wmode;

  for (const char* p = mode; *p; ++p) {
    wmode += static_cast<wchar_t>(*p);
  }

  _wfopen_s(file, fs_path.c_str(), wmode.c_str());
}

Result OpenNewFile(FILE** file, const std::string& path) {
  *file = nullptr;

  std::filesystem::path fs_path = ToPath(path);

  HANDLE handle = CreateFileW(fs_path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                              FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);

  if (handle == INVALID_HANDLE_VALUE) {
    return Result::kFailure;
  }

  const int fd = _open_osfhandle(reinterpret_cast<intptr_t>(handle), _O_WRONLY | _O_BINARY);

  if (fd == -1) {
    // LCOV_EXCL_START
    CloseHandle(handle);
    _wunlink(fs_path.c_str());
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  *file = _fdopen(fd, "wb");

  if (*file == nullptr) {
    // LCOV_EXCL_START
    _close(fd);
    _wunlink(fs_path.c_str());
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  return Result::kSuccess;
}
