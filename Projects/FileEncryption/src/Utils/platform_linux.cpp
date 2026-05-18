/**
 * @file	platform_linux.h
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

#include "Utils/platform.h"

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

int GetProcNum() {
  return static_cast<int>(std::thread::hardware_concurrency());
}

int Random(uint8_t* dst, size_t size) {
  size_t remaining = size;

  while (remaining > 0) {
    ssize_t result = getrandom(dst, remaining, 0);

    if (result == -1) {
      if (errno == EINTR) {
        continue;
      }

      return -1;
    }

    dst += result;
    remaining -= result;
  }

  return 0;
}

int RemoveFile(const std::string& path) {
  return unlink(path.c_str());
}

int Seek(FILE* file, int64_t offset, int origin) {
  return fseeko(file, offset, origin);
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