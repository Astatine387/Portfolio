/**
 * @file	platform_linux.cpp
 * @brief	Implementation of utility functions for Linux
 * @author	Astatine387
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

/* RENAME_NOREPLACE, spelled out rather than taken from <linux/fs.h>, because that header conflicts with the C
 * library's own definitions on some distributions. The value is kernel ABI and cannot change. */

constexpr unsigned int kRenameNoReplace = 1U;

}  // namespace

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

RenameStatus RenameFileNoReplace(const std::string& src, const std::string& dst) {
  /* Three ways to take the destination name, tried in order of how much the file system does on its own. Each one
   * falls through only on the errors that mean the file system cannot do it, never on a real failure, so a refusal is
   * still reported as a refusal. None of them can cross a file system, which is why the source has to be a sibling of
   * the destination. */

  /* 1. renameat2 with RENAME_NOREPLACE: one atomic step that fails with EEXIST if the name is taken. Available on
   *    ext4, XFS, Btrfs, F2FS and tmpfs. */

#ifdef SYS_renameat2
  if (syscall(SYS_renameat2, AT_FDCWD, src.c_str(), AT_FDCWD, dst.c_str(), kRenameNoReplace) == 0) {
    return RenameStatus::kOk;
  }

  if (errno == EEXIST) {
    return RenameStatus::kExists;
  }

  /* EINVAL is what a file system without flag support answers, ENOSYS a kernel older than 3.15 */

  if (errno != EINVAL && errno != ENOSYS && errno != EOPNOTSUPP) {
    return RenameStatus::kFailure;
  }
#endif

  /* Everything below is held off the coverage report. It is not an error path a test could provoke: it runs only
   * where RENAME_NOREPLACE is missing, and step 1 answers every call definitively on ext4, XFS, Btrfs and tmpfs,
   * which is all a test or a CI runner has to hand. Reaching it takes a FAT, exFAT or NFS mount rather than a test
   * case, so counting it as untested code would only be reporting the file system the suite happened to run on. */

  // LCOV_EXCL_START

  /* 2. link(): the same guarantee by another route, since a taken name gives EEXIST. This covers file systems that
   *    have hard links but no flag support in rename, such as NFS and ntfs-3g. */

  if (link(src.c_str(), dst.c_str()) == 0) {
    /* The destination already holds the data, so failing to drop the source link is not worth reporting */

    static_cast<void>(unlink(src.c_str()));

    return RenameStatus::kOk;
  }

  if (errno == EEXIST) {
    return RenameStatus::kExists;
  }

  if (errno != EPERM && errno != EOPNOTSUPP) {
    return RenameStatus::kFailure;
  }

  /* 3. A file system with no hard links at all answers EPERM above, and FAT32 and exFAT are exactly where a vault
   *    carried on a memory stick tends to be written. There is no atomic no-replace rename to fall back on there, so
   *    the name is taken by an exclusive create instead, which is atomic on FAT as well. The rename that follows
   *    replaces a placeholder this program made a moment earlier, never a file that belonged to anyone else. */

  const int fd = open(dst.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, S_IRUSR | S_IWUSR);

  if (fd == -1) {
    return errno == EEXIST ? RenameStatus::kExists : RenameStatus::kFailure;
  }

  close(fd);

  if (rename(src.c_str(), dst.c_str()) != 0) {
    /* The name was taken and then not used, so it is given back rather than left as an empty file */

    static_cast<void>(unlink(dst.c_str()));

    return RenameStatus::kFailure;
  }

  return RenameStatus::kOk;
  // LCOV_EXCL_STOP
}

Result ResolvePath(const std::string& path, std::string& out) {
  std::error_code ec;

  /* canonical rather than a read of the link's own target, because a target may be another link and may be relative to
   * the directory the link sits in. The error_code overload is the one that reports a path that does not resolve as a
   * failure instead of throwing, which this build has no way to catch. */

  const std::filesystem::path real = std::filesystem::canonical(path, ec);

  if (ec) {
    return Result::kFailure;
  }

  out = real.string();

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

  const int res = fsync(fd);
  const int err = errno;

  close(fd);

  /* POSIX does not require fsync on a directory descriptor to be supported, and file systems that do not support it
   * (CIFS among them) answer EINVAL or EBADF. There is nothing to flush on those, which is not a failure; a real
   * error such as EIO still is. */

  if (res != 0 && err != EINVAL && err != EBADF) {
    return Result::kFailure;
  }

  return Result::kSuccess;
}

void OpenFile(FILE** file, const std::string& path, const char* mode) {
  *file = fopen(path.c_str(), mode);
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
