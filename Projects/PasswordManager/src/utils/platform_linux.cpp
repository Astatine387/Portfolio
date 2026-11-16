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
#include <cstdlib>
#include <filesystem>
#include <system_error>
#include <thread>

#include "utils/platform.h"

namespace {

constexpr unsigned int kRenameNoReplace = 1U;

}  // namespace

bool FileExists(const std::string& path) {
  std::error_code ec;

  return std::filesystem::status(path, ec).type() !=
         std::filesystem::file_type::not_found;
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

RenameStatus RenameFileNoReplace(const std::string& src,
                                 const std::string& dst) {
#ifdef SYS_renameat2
  if (syscall(SYS_renameat2, AT_FDCWD, src.c_str(), AT_FDCWD, dst.c_str(),
              kRenameNoReplace) == 0) {
    return RenameStatus::kOk;
  }

  if (errno == EEXIST) {
    return RenameStatus::kExists;
  }

  if (errno != EINVAL && errno != ENOSYS && errno != EOPNOTSUPP) {
    return RenameStatus::kFailure;
  }
#endif
  // LCOV_EXCL_START
  if (link(src.c_str(), dst.c_str()) == 0) {
    static_cast<void>(unlink(src.c_str()));

    return RenameStatus::kOk;
  }

  if (errno == EEXIST) {
    return RenameStatus::kExists;
  }

  if (errno != EPERM && errno != EOPNOTSUPP) {
    return RenameStatus::kFailure;
  }

  const int fd =
      open(dst.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
           S_IRUSR | S_IWUSR);

  if (fd == -1) {
    return errno == EEXIST ? RenameStatus::kExists : RenameStatus::kFailure;
  }

  close(fd);

  if (rename(src.c_str(), dst.c_str()) != 0) {
    static_cast<void>(unlink(dst.c_str()));

    return RenameStatus::kFailure;
  }

  return RenameStatus::kOk;
  // LCOV_EXCL_STOP
}

Result ResolvePath(const std::string& path, std::string& out) {
  std::error_code ec;

  const std::filesystem::path real = std::filesystem::canonical(path, ec);

  if (ec) {
    return Result::kFailure;
  }

  out = real.string();

  return Result::kSuccess;
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

  const int res = fsync(fd);
  const int err = errno;

  close(fd);

  /* A file system without directory fsync answers EINVAL or EBADF */

  if (res != 0 && err != EINVAL && err != EBADF) {
    return Result::kFailure;
  }

  return Result::kSuccess;
}

void OpenFile(FILE** file, const std::string& path, const char* mode) {
  *file = fopen(path.c_str(), mode);
}

Result OpenRegularFile(FILE** file, const std::string& path) {
  *file = nullptr;

  const int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK);

  if (fd == -1) {
    return Result::kFailure;
  }

  struct stat st = {};

  if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
    close(fd);
    return Result::kFailure;
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

// cppcheck-suppress constParameterReference
Result OpenTempFile(FILE** file, std::string& path) {
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
