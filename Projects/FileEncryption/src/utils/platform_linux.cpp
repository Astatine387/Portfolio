/**
 * @file    platform_linux.cpp
 * @brief   Implementation of utility functions for Linux
 * @author  Astatine387
 */

#include <fcntl.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <filesystem>
#include <thread>

#include "utils/platform.h"

namespace {

constexpr unsigned int kRenameNoReplace = 1U;

}  // namespace

bool FileExists(const std::string& path) {
  return std::filesystem::exists(path);
}

int64_t GetFileSize(FILE* file) {
  struct stat st = {};

  /* Fails if it isn't a regular file */

  if (fstat(fileno(file), &st) != 0 || !S_ISREG(st.st_mode)) {
    return -1;
  }

  /* Get the file size */

  if (fseeko(file, 0, SEEK_END)) {
    return -1;  // LCOV_EXCL_LINE
  }

  int64_t res = ftello(file);

  /* Reset the cursor */

  if (fseeko(file, 0, SEEK_SET)) {
    return -1;  // LCOV_EXCL_LINE
  }

  return res;
}

Result Random(uint8_t* dst, size_t size) {
  size_t rem = size;

  while (rem > 0) {
    /* getrandom only promises to fill a buffer of up to 256 bytes in one call,
     * so a buffer larger than it needs a loop */

    ssize_t result = getrandom(dst, rem, 0);

    if (result == -1) {
      // LCOV_EXCL_START
      if (errno == EINTR) {
        continue;
      }

      return Result::kFailure;
      // LCOV_EXCL_STOP
    }

    dst += result;
    rem -= static_cast<size_t>(result);
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
#ifdef SYS_renameat2
  if (syscall(SYS_renameat2, AT_FDCWD, src.c_str(), AT_FDCWD, dst.c_str(),
              kRenameNoReplace) == 0) {
    return Result::kSuccess;
  }

  if (errno != EINVAL && errno != ENOSYS && errno != EOPNOTSUPP) {
    return Result::kFailure;
  }
#endif
  // LCOV_EXCL_START
  if (link(src.c_str(), dst.c_str()) == 0) {
    static_cast<void>(unlink(src.c_str()));

    return Result::kSuccess;
  }

  if (errno != EPERM && errno != EOPNOTSUPP) {
    return Result::kFailure;
  }

  const int fd =
      open(dst.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
           S_IRUSR | S_IWUSR);

  if (fd == -1) {
    return Result::kFailure;
  }

  close(fd);

  if (rename(src.c_str(), dst.c_str()) != 0) {
    static_cast<void>(unlink(dst.c_str()));

    return Result::kFailure;
  }

  return Result::kSuccess;
  // LCOV_EXCL_STOP
}

Result SyncFile(FILE* file) {
  /* Push the stdio buffer into the kernel */

  if (fflush(file)) {
    return Result::kFailure;
  }

  /* Push the kernel's page cache onto the disk */

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

Result Seek(FILE* file, int64_t offset, int origin) {
  if (fseeko(file, offset, origin)) {
    return Result::kFailure;
  }

  return Result::kSuccess;
}

void OpenFile(FILE** file, const std::string& path, const char* mode) {
  *file = fopen(path.c_str(), mode);
}

Result OpenSourceFile(FILE** file, const std::string& path) {
  *file = nullptr;

  const int fd =
      open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);

  if (fd == -1) {
    return Result::kFailure;
  }

  struct stat st = {};

  if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
    close(fd);
    return Result::kFailure;
  }

  if (st.st_size == 0) {
    uint8_t probe = 0;

    if (pread(fd, &probe, 1, 0) != 0) {
      close(fd);
      return Result::kFailure;
    }
  }

  const int flags = fcntl(fd, F_GETFL);

  if (flags == -1 || fcntl(fd, F_SETFL, flags & ~O_NONBLOCK) == -1) {
    // LCOV_EXCL_START
    close(fd);
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  *file = fdopen(fd, "rb");

  if (*file == nullptr) {
    // LCOV_EXCL_START
    close(fd);
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  return Result::kSuccess;
}

Result OpenNewFile(FILE** file, const std::string& path) {
  *file = nullptr;

  const int fd =
      open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
           S_IRUSR | S_IWUSR);

  if (fd == -1) {
    return Result::kFailure;
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
