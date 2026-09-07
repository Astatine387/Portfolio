/**
 * @file	platform_win32.cpp
 * @brief	Implementation of utility functions for Windows
 * @author	Astatine387
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

std::filesystem::path ToPath(const std::string& path) {
  /* Going through u8string makes std::filesystem read the bytes as UTF-8. A plain char string would be
   * decoded with the active code page instead, mangling every non-ASCII file name. */

  return std::filesystem::path(std::u8string(reinterpret_cast<const char8_t*>(path.data()), path.size()));
}

}  // namespace

bool FileExists(const std::string& path) {
  std::filesystem::path fs_path = ToPath(path);
  return std::filesystem::exists(fs_path);
}

int64_t GetFileSize(FILE* file) {
  /* A size is only meaningful for a regular file, so a stream on a console, a pipe or a device is a
   * failure here rather than a number. The type comes from the descriptor, which is what makes this hold
   * for a stream that reached here without going through OpenSourceFile. */

  struct _stat64 st = {};

  if (_fstat64(_fileno(file), &st) != 0 || (st.st_mode & _S_IFMT) != _S_IFREG) {
    return -1;
  }

  /* Measuring moves the position, so it is put back at the start and the caller can read from there */

  if (_fseeki64(file, 0, SEEK_END)) {
    return -1;  // LCOV_EXCL_LINE  a regular file is always seekable
  }

  int64_t size = _ftelli64(file);

  if (_fseeki64(file, 0, SEEK_SET)) {
    return -1;  // LCOV_EXCL_LINE
  }

  return size;
}

Result Random(uint8_t* dst, size_t size) {
  /* Unlike getrandom on the Linux side, this fills the whole buffer or fails, so there is no loop */

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

  /* MOVEFILE_REPLACE_EXISTING is deliberately absent, so the move fails instead of overwriting an
   * existing destination. MOVEFILE_WRITE_THROUGH returns only once the new directory entry is on the
   * disk, which is what lets SyncDir here be a plain open. */

  if (!MoveFileExW(src_path.c_str(), dst_path.c_str(), MOVEFILE_WRITE_THROUGH)) {
    return Result::kFailure;
  }

  return Result::kSuccess;
}

Result SyncFile(FILE* file) {
  /* Two layers of buffering: fflush pushes the stdio buffer down to the operating system, and
   * FlushFileBuffers below pushes the system's cache onto the disk */

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

Result SyncDir(const std::string& path) {
  std::filesystem::path dir = ToPath(path).parent_path();

  HANDLE handle = CreateFileW(dir.empty() ? L"." : dir.c_str(), GENERIC_READ,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                              FILE_FLAG_BACKUP_SEMANTICS, nullptr);

  if (handle == INVALID_HANDLE_VALUE) {
    return Result::kFailure;
  }

  /* Windows has no directory fsync. MOVEFILE_WRITE_THROUGH in RenameFile already puts the directory
   * entry on the disk, so opening the directory is the only step that can fail here. */

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

  /* Widening one byte at a time is only correct for ASCII, which is all a stdio mode string ever is */

  for (const char* p = mode; *p; ++p) {
    wmode += static_cast<wchar_t>(*p);
  }

  _wfopen_s(file, fs_path.c_str(), wmode.c_str());
}

Result OpenSourceFile(FILE** file, const std::string& path) {
  *file = nullptr;

  std::filesystem::path fs_path = ToPath(path);

  /* FILE_FLAG_OPEN_REPARSE_POINT opens a reparse point instead of following it, matching O_NOFOLLOW on
   * the Linux side, so a symbolic link or a junction arrives here as itself and is rejected below rather
   * than silently read through. Sharing reads but not writes keeps a file another process is still
   * writing from being taken as a source, which is what stops its size from moving under the reader. */

  HANDLE handle = CreateFileW(fs_path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                              FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);

  if (handle == INVALID_HANDLE_VALUE) {
    return Result::kFailure;
  }

  BY_HANDLE_FILE_INFORMATION info = {};

  /* Asking the handle rather than the path, so what was opened is what is judged and the answer cannot
   * change in between. FILE_TYPE_DISK is the part that rules out a console or a named pipe, which the
   * attributes alone would not. */

  if (!GetFileInformationByHandle(handle, &info) ||
      (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0 ||
      GetFileType(handle) != FILE_TYPE_DISK) {
    CloseHandle(handle);
    return Result::kFailure;
  }

  const int fd = _open_osfhandle(reinterpret_cast<intptr_t>(handle), _O_RDONLY | _O_BINARY);

  if (fd == -1) {
    // LCOV_EXCL_START
    CloseHandle(handle);
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  /* The descriptor owns the handle from here, so closing it is what closes the handle */

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

  /* CREATE_NEW refuses a path that is already taken and FILE_FLAG_OPEN_REPARSE_POINT opens a reparse
   * point instead of following it, together matching O_EXCL | O_NOFOLLOW on the Linux side. The zero
   * share mode keeps other processes out of the file while it is being written. */

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
