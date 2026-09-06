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
#include <filesystem>
#include <thread>

#include "utils/platform.h"

bool FileExists(const std::string& path) {
  return std::filesystem::exists(path);
}

int64_t GetFileSize(FILE* file) {
  /* Measuring moves the position, so it is put back at the start and the caller can read from there */

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
  /* getrandom only promises to fill a buffer of up to 256 bytes in one call, so anything larger loops */

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
    remaining -= static_cast<size_t>(result);
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
  /* link() rather than rename(): rename() would silently replace an existing destination, while link()
   * fails with EEXIST. The cost is that it cannot cross a filesystem, so the source has to be a sibling
   * of the destination. */

  if (link(src.c_str(), dst.c_str())) {
    return Result::kFailure;
  }

  /* The destination already holds the data, so failing to drop the source link is not worth reporting */

  static_cast<void>(unlink(src.c_str()));

  return Result::kSuccess;
}

Result SyncFile(FILE* file) {
  /* Two layers of buffering: fflush pushes the stdio buffer into the kernel, fsync pushes the kernel's
   * page cache onto the disk. Either one alone leaves data that a power cut can still take. */

  if (fflush(file)) {
    return Result::kFailure;
  }

  if (fsync(fileno(file))) {
    return Result::kFailure;
  }

  return Result::kSuccess;
}

Result SyncDir(const std::string& path) {
  /* Syncing the file leaves the new directory entry in the cache, so a power cut could still take the
   * rename away; only an fsync on the parent directory makes the entry itself durable */

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

Result OpenNewFile(FILE** file, const std::string& path) {
  *file = nullptr;

  /* O_EXCL refuses a path that is already taken and O_NOFOLLOW refuses a symlink at the final component,
   * so neither an existing file nor a planted link can be written through. The mode leaves the output
   * readable by its owner alone. */

  const int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, S_IRUSR | S_IWUSR);

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
