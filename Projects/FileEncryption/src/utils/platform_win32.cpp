/**
 * @file    platform_win32.cpp
 * @brief   Implementation of utility functions for Windows
 * @author  Astatine387
 */

#include <windows.h>

#include <bcrypt.h>
#include <fcntl.h>
#include <io.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <filesystem>

#include "utils/platform.h"

namespace {

/**
 * @brief   Convert std::string file path to std::filesystem::path
 * @param   path  file path, in std::string
 * @return  file path, in std::filesystem::path
 */
std::filesystem::path ToPath(const std::string& path) {
  return std::filesystem::path(std::u8string(
      reinterpret_cast<const char8_t*>(path.data()), path.size()));
}

}  // namespace

bool FileExists(const std::string& path) {
  std::filesystem::path fs_path = ToPath(path);
  return std::filesystem::exists(fs_path);
}

int64_t GetFileSize(FILE* file) {
  struct _stat64 st = {};

  /* Fails if it isn't a regular file */

  if (_fstat64(_fileno(file), &st) != 0 || (st.st_mode & _S_IFMT) != _S_IFREG) {
    return -1;
  }

  /* Get the file size */

  if (_fseeki64(file, 0, SEEK_END)) {
    return -1;  // LCOV_EXCL_LINE
  }

  int64_t res = _ftelli64(file);

  /* Reset the cursor */

  if (_fseeki64(file, 0, SEEK_SET)) {
    return -1;  // LCOV_EXCL_LINE
  }

  return res;
}

Result Random(uint8_t* dst, size_t size) {
  if (BCryptGenRandom(nullptr, dst, static_cast<ULONG>(size),
                      BCRYPT_USE_SYSTEM_PREFERRED_RNG)) {
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

  if (!MoveFileExW(src_path.c_str(), dst_path.c_str(),
                   MOVEFILE_WRITE_THROUGH)) {
    return Result::kFailure;
  }

  return Result::kSuccess;
}

Result SyncFile(FILE* file) {
  /* Push the stdio buffer into the kernel */

  if (fflush(file)) {
    return Result::kFailure;
  }

  /* Get file handle */

  const intptr_t ptr = _get_osfhandle(_fileno(file));

  HANDLE handle =
      reinterpret_cast<HANDLE>(ptr);  // NOLINT(performance-no-int-to-ptr)

  if (handle == INVALID_HANDLE_VALUE) {
    return Result::kFailure;
  }

  /* Push the kernel's page cache onto the disk */

  if (!FlushFileBuffers(handle)) {
    return Result::kFailure;
  }

  return Result::kSuccess;
}

Result SyncDir(const std::string& path) {
  std::filesystem::path dir = ToPath(path).parent_path();

  HANDLE handle =
      CreateFileW(dir.empty() ? L"." : dir.c_str(), GENERIC_READ,
                  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                  nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);

  if (handle == INVALID_HANDLE_VALUE) {
    return Result::kFailure;
  }

  CloseHandle(handle);

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

Result OpenSourceFile(FILE** file, const std::string& path) {
  *file = nullptr;

  std::filesystem::path fs_path = ToPath(path);

  HANDLE handle = CreateFileW(
      fs_path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
      FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);

  if (handle == INVALID_HANDLE_VALUE) {
    return Result::kFailure;
  }

  BY_HANDLE_FILE_INFORMATION info = {};

  if (!GetFileInformationByHandle(handle, &info) ||
      (info.dwFileAttributes &
       (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0 ||
      GetFileType(handle) != FILE_TYPE_DISK) {
    CloseHandle(handle);
    return Result::kFailure;
  }

  const int fd = _open_osfhandle(reinterpret_cast<intptr_t>(handle),
                                 _O_RDONLY | _O_BINARY);

  if (fd == -1) {
    // LCOV_EXCL_START
    CloseHandle(handle);
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  *file = _fdopen(fd, "rb");

  if (*file == nullptr) {
    // LCOV_EXCL_START
    _close(fd);
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  return Result::kSuccess;
}

Result OpenNewFile(FILE** file, const std::string& path) {
  *file = nullptr;

  std::filesystem::path fs_path = ToPath(path);

  HANDLE handle = CreateFileW(
      fs_path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
      FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);

  if (handle == INVALID_HANDLE_VALUE) {
    return Result::kFailure;
  }

  const int fd = _open_osfhandle(reinterpret_cast<intptr_t>(handle),
                                 _O_WRONLY | _O_BINARY);

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
