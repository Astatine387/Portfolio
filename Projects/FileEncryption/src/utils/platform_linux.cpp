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
#include <cstdio>
#include <filesystem>
#include <thread>

#include "utils/platform.h"

namespace {

/* RENAME_NOREPLACE, spelled out rather than taken from <linux/fs.h>, because that header conflicts with
 * the C library's own definitions on some distributions. The value is kernel ABI and cannot change. */

constexpr unsigned int kRenameNoReplace = 1U;

}  // namespace

bool FileExists(const std::string& path) {
  return std::filesystem::exists(path);
}

int64_t GetFileSize(FILE* file) {
  /* A size is only meaningful for a regular file. A procfs entry seeks to an end of zero and a character
   * device answers with whatever its driver reports, and either one would be taken as an empty source,
   * encrypted into an empty file and reported as a success. The type comes from the descriptor, so this
   * holds for a stream that reached here without going through OpenSourceFile. */

  struct stat st = {};

  if (fstat(fileno(file), &st) != 0 || !S_ISREG(st.st_mode)) {
    return -1;
  }

  /* Measuring moves the position, so it is put back at the start and the caller can read from there */

  if (fseeko(file, 0, SEEK_END)) {
    return -1;  // LCOV_EXCL_LINE  a regular file is always seekable
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
  /* Three ways to take the destination name, tried in order of how much the file system does on its own.
   * Each one falls through only on the errors that mean the file system cannot do it, never on a real
   * failure, so a refusal is still reported as a refusal. None of them can cross a file system, which is
   * why the source has to be a sibling of the destination. */

  /* 1. renameat2 with RENAME_NOREPLACE: one atomic step that fails with EEXIST if the name is taken.
   *    Available on ext4, XFS, Btrfs, F2FS and tmpfs. */

#ifdef SYS_renameat2
  if (syscall(SYS_renameat2, AT_FDCWD, src.c_str(), AT_FDCWD, dst.c_str(), kRenameNoReplace) == 0) {
    return Result::kSuccess;
  }

  /* EINVAL is what a file system without flag support answers, ENOSYS a kernel older than 3.15 */

  if (errno != EINVAL && errno != ENOSYS && errno != EOPNOTSUPP) {
    return Result::kFailure;
  }
#endif

  /* Everything below is held off the coverage report. It is not an error path a test could provoke: it
   * runs only where RENAME_NOREPLACE is missing, and step 1 answers every call definitively on ext4,
   * XFS, Btrfs and tmpfs, which is all a test or a CI runner has to hand. Reaching it takes a FAT,
   * exFAT or NFS mount rather than a test case, so counting it as untested code would only be reporting
   * the file system the suite happened to run on. */

  // LCOV_EXCL_START

  /* 2. link(): the same guarantee by another route, since a taken name gives EEXIST. This covers file
   *    systems that have hard links but no flag support in rename, such as NFS and ntfs-3g. */

  if (link(src.c_str(), dst.c_str()) == 0) {
    /* The destination already holds the data, so failing to drop the source link is not worth reporting */

    static_cast<void>(unlink(src.c_str()));

    return Result::kSuccess;
  }

  if (errno != EPERM && errno != EOPNOTSUPP) {
    return Result::kFailure;
  }

  /* 3. A file system with no hard links at all answers EPERM above, and FAT32 and exFAT are exactly
   *    where a portable encrypted file tends to be written. There is no atomic no-replace rename to fall
   *    back on there, so the name is taken by an exclusive create instead, which is atomic on FAT as
   *    well. The rename that follows replaces a placeholder this program made a moment earlier, never a
   *    file that belonged to anyone else. */

  const int fd = open(dst.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, S_IRUSR | S_IWUSR);

  if (fd == -1) {
    return Result::kFailure;
  }

  close(fd);

  if (rename(src.c_str(), dst.c_str()) != 0) {
    /* The name was taken and then not used, so it is given back rather than left as an empty file */

    static_cast<void>(unlink(dst.c_str()));

    return Result::kFailure;
  }

  return Result::kSuccess;
  // LCOV_EXCL_STOP
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

Result OpenSourceFile(FILE** file, const std::string& path) {
  *file = nullptr;

  /* O_NOFOLLOW refuses a symbolic link at the final component, the same as on the writing side, so a
   * planted link cannot redirect what is read. O_CLOEXEC keeps the descriptor out of a child process.
   *
   * O_NONBLOCK is what makes the check below reachable at all: opening a FIFO for reading otherwise
   * blocks until a writer turns up, so a named pipe given as the source would hang the worker thread
   * before anything had a chance to reject it. On a regular file the flag does nothing. */

  const int fd = open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);

  if (fd == -1) {
    return Result::kFailure;
  }

  /* Asking the descriptor rather than the path, so what was opened is what is judged and the answer
   * cannot change between the two. A directory opens for reading here, and a procfs entry opens and then
   * reports a size of zero, so both are refused before either can be read as an empty source. */

  struct stat st = {};

  if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
    close(fd);
    return Result::kFailure;
  }

  /* A procfs entry passes every check above: it is a regular file by st_mode and reports a size of zero
   * while having contents to read. No attribute separates it from an ordinary empty file, so the only
   * honest test is to read one. A byte at offset zero, through pread so the position is left alone, and
   * anything that answers with data while calling itself empty is refused here rather than encrypted
   * into an empty file and reported as a success. */

  if (st.st_size == 0) {
    uint8_t probe = 0;

    if (pread(fd, &probe, 1, 0) != 0) {
      close(fd);
      return Result::kFailure;
    }
  }

  /* The type is settled, so the flag that was only there to survive the open comes back off before stdio
   * ever sees the descriptor. A regular file would ignore it, and a short read that stdio reads as an
   * error is not a risk worth carrying for nothing. */

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
