/**
 * @file	platform_win32.cpp
 * @brief	Implementation of utility functions for Windows
 * @author	Astatine387
 */

#include <windows.h>

#include <bcrypt.h>
#include <fcntl.h>
#include <io.h>

#include <array>
#include <filesystem>

#include "utils/platform.h"

namespace {

std::filesystem::path ToPath(const std::string& path) {
  return std::filesystem::path(std::u8string(reinterpret_cast<const char8_t*>(path.data()), path.size()));
}

bool CheckNameCollision(DWORD err) {
  return err == ERROR_FILE_EXISTS || err == ERROR_ALREADY_EXISTS;
}

}  // namespace

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
  std::filesystem::path fs_path = ToPath(path);
  return std::filesystem::exists(fs_path);
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

  if (!MoveFileExW(src_path.c_str(), dst_path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
    return Result::kFailure;  // LCOV_EXCL_LINE
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
  /* Windows has no directory-fsync; rename durability is handled by MOVEFILE_WRITE_THROUGH in RenameFile */
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

Result OpenTempFile(FILE** file, const std::string& path, [[maybe_unused]] const std::string& model) {
  *file = nullptr;

  constexpr int kAttempts = 16;
  constexpr size_t kSuffixLen = 6;
  constexpr std::string_view kPool = "abcdefghijklmnopqrstuvwxyz0123456789";

  if (path.size() < kSuffixLen) {
    return Result::kFailure;  // LCOV_EXCL_LINE
  }

  const size_t suffix_pos = path.size() - kSuffixLen;

  for (int i = 0; i < kAttempts; i++) {
    for (size_t j = 0; j < kSuffixLen; j++) {
      uint32_t idx = 0;

      if (RandomRange(&idx, 0, static_cast<uint32_t>(kPool.size()) - 1) == Result::kFailure) {
        return Result::kFailure;  // LCOV_EXCL_LINE
      }

      path[suffix_pos + j] = kPool[idx];
    }

    std::filesystem::path fs_path = ToPath(path);

    HANDLE handle = CreateFileW(fs_path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);

    if (handle == INVALID_HANDLE_VALUE) {
      /* Give up on a denied ACL, a missing directory or a full disk */

      if (!CheckNameCollision(GetLastError())) {
        return Result::kFailure;
      }

      continue;
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

  return Result::kFailure;  // LCOV_EXCL_LINE
}
