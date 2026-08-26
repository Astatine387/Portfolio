/**
 * @file	platform_linux.cpp
 * @brief	Implementation of utility functions for Linux
 * @author	Astatine387
 */

#include <fcntl.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstdlib>
#include <filesystem>
#include <thread>

#include "utils/platform.h"

bool FileExists(const std::string& path) {
  return std::filesystem::exists(path);
}

int64_t GetFileSize(FILE* file) {
  if (fseeko(file, 0, SEEK_END)) {
    return -1;
  }

  int64_t size = ftello(file);

  if (fseeko(file, 0, SEEK_SET)) {
    return -1;  // LCOV_EXCL_LINE
  }

  return size;
}

Result Random(uint8_t* dst, size_t size) {
  size_t rem = size;

  while (rem > 0) {
    ssize_t res = getrandom(dst, rem, 0);

    if (res <= 0) {
      // LCOV_EXCL_START
      if (res == -1 && errno == EINTR) {
        continue;
      }

      return Result::kFailure;
      // LCOV_EXCL_STOP
    }

    const size_t len = static_cast<size_t>(res);

    dst += len;
    rem -= len;
  }

  return Result::kSuccess;
}

Result RemoveFile(const std::string& path) {
  if (unlink(path.c_str())) {
    return Result::kFailure;
  }

  return Result::kSuccess;
}

Result RenameFile(const std::string& src, const std::string& dst) {
  if (rename(src.c_str(), dst.c_str())) {
    return Result::kFailure;
  }

  return Result::kSuccess;
}

Result SyncFile(FILE* file) {
  if (fflush(file)) {
    return Result::kFailure;
  }

  if (fsync(fileno(file))) {
    return Result::kFailure;
  }

  return Result::kSuccess;
}

Result SyncDir(const std::string& path) {
  std::filesystem::path dir = std::filesystem::path(path).parent_path();

  int fd = open(dir.empty() ? "." : dir.c_str(), O_RDONLY | O_DIRECTORY);

  if (fd == -1) {
    return Result::kFailure;
  }

  int res = fsync(fd);

  close(fd);

  if (res) {
    return Result::kFailure;
  }

  return Result::kSuccess;
}

void OpenFile(FILE** file, const std::string& path, const char* mode) {
  *file = fopen(path.c_str(), mode);
}

Result OpenTempFile(FILE** file, std::string& path, const std::string& model) {
  *file = nullptr;

  const int fd = mkstemp(path.data());

  if (fd == -1) {
    return Result::kFailure;
  }

  if (fcntl(fd, F_SETFD, FD_CLOEXEC) == -1) {
    // LCOV_EXCL_START
    close(fd);
    unlink(path.c_str());
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  struct stat st = {};

  if (!model.empty() && stat(model.c_str(), &st) == 0) {
    fchmod(fd, st.st_mode & 07777);
  }

  *file = fdopen(fd, "wb");

  if (*file == nullptr) {
    // LCOV_EXCL_START
    close(fd);
    unlink(path.c_str());
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  return Result::kSuccess;
}
