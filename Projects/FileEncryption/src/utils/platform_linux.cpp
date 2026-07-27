/**
 * @file	platform_linux.cpp
 * @brief	Implementation of utility functions for Linux
 * @author	Astatine387
 */

#include <sys/random.h>
#include <unistd.h>

#include <cerrno>
#include <filesystem>
#include <thread>

#include "utils/platform.h"

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

bool FileExists(const std::string& path) {
  return std::filesystem::exists(path);
}

Result Random(uint8_t* dst, size_t size) {
  size_t remaining = size;

  while (remaining > 0) {
    ssize_t result = getrandom(dst, remaining, 0);

    if (result == -1) {
      // LCOV_EXCL_START
      if (errno == EINTR) {
        continue;
      }

      return Result::kFailure;
      // LCOV_EXCL_STOP
    }

    dst += result;
    remaining -= result;
  }

  return Result::kSuccess;
}

Result RemoveFile(const std::string& path) {
  if (unlink(path.c_str())) {
    return Result::kFailure;
  }

  return Result::kSuccess;
}

Result Seek(FILE* file, int64_t offset, int origin) {
  if (fseeko(file, offset, origin)) {
    return Result::kFailure;
  }

  return Result::kSuccess;
}

void OpenFile(FILE** file, const std::string& path, const char* mode) {
  *file = fopen(path.c_str(), mode);
}