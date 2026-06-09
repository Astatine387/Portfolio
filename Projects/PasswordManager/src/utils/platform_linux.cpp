/**
 * @file	platform_linux.cpp
 * @brief	Implementation of utility functions for Linux
 * @author	Astatine387
 */

#include <sys/mman.h>
#include <sys/random.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <filesystem>
#include <thread>

#include "utils/platform.h"

int64_t GetFileSize(FILE* file) {
  if (fseeko(file, 0, SEEK_END)) {
    return -1;
  }

  int64_t size = ftello(file);
  rewind(file);
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
      if (errno == EINTR) {
        continue;
      }

      return Result::kFailure;
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

Result RenameFile(const std::string& src, const std::string& dst) {
  if (rename(src.c_str(), dst.c_str())) {
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

Result SyncFile(FILE* file) {
  if (fflush(file)) {
    return Result::kFailure;
  }

  if (fsync(fileno(file))) {
    return Result::kFailure;
  }

  return Result::kSuccess;
}

void Lock(void* ptr, size_t size) {
  mlock(ptr, size);
}

void OpenFile(FILE** file, const std::string& path, const char* mode) {
  *file = fopen(path.c_str(), mode);
}

void Unlock(void* ptr, size_t size) {
  munlock(ptr, size);
}

void Wipe(void* ptr, size_t size) {
#if defined(__GLIBC__) && __GLIBC__ >= 2 && __GLIBC_MINOR__ >= 25
  explicit_bzero(ptr, size);
#else
  volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);

  while (size--) {
    *p++ = 0;
  }

  __asm__ __volatile__("" : : "r"(ptr) : "memory");
#endif
}