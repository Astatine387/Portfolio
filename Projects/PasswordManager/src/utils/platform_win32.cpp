/**
 * @file    platform_win32.cpp
 * @brief   Implementation of utility functions for Windows
 * @author  Astatine387
 */

#include <windows.h>

#include <bcrypt.h>
#include <fcntl.h>
#include <io.h>
#include <sddl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <array>
#include <filesystem>
#include <memory>
#include <system_error>
#include <vector>

#include "utils/platform.h"

namespace {

/**
 * @brief   Convert std::string file path to std::filesystem::path
 * @param   path  file path, in std::string
 * @return  file path, in std::filesystem::path
 */
std::filesystem::path ToPath(const std::string& path) {
  return std::filesystem::path(std::u8string(
      reinterpret_cast<const char8_t*>(path.data()), path.size()));
}

/**
 * @brief   Check whether an error code means the name was already taken
 * @param   err   Error code from GetLastError
 * @return  true if the name was taken
 */
bool CheckNameCollision(DWORD err) {
  return err == ERROR_FILE_EXISTS || err == ERROR_ALREADY_EXISTS;
}

/**
 * @brief   Releases memory the security APIs allocated on the local heap
 */
struct LocalGuard {
  void operator()(void* mem) const noexcept { LocalFree(mem); }
};

/**
 * @brief   Closes a kernel handle
 */
struct HandleGuard {
  void operator()(HANDLE handle) const noexcept { CloseHandle(handle); }
};

/**
 * @brief   Owning handles for the three allocations an owner-only security
 * descriptor is built out of
 */
using SdPtr = std::unique_ptr<void, LocalGuard>;
using SidPtr = std::unique_ptr<wchar_t, LocalGuard>;
using TokenPtr = std::unique_ptr<void, HandleGuard>;

/**
 * @brief   Build a security descriptor that grants the account this process
 * runs as everything, and nobody else anything
 * @param   sd  Receives the descriptor on success, left as it was on failure
 * @return  kSuccess on success, kFailure on failure
 */
Result MakeOwnerOnlyDescriptor(SdPtr& sd) {
  HANDLE raw_token = nullptr;

  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw_token)) {
    return Result::kFailure;  // LCOV_EXCL_LINE
  }

  const TokenPtr token(raw_token);

  /* Ask for the size of the TokenUser answer first */

  DWORD len = 0;

  if (GetTokenInformation(token.get(), TokenUser, nullptr, 0, &len) ||
      len < sizeof(TOKEN_USER)) {
    return Result::kFailure;  // LCOV_EXCL_LINE
  }

  /* operator new aligns the buffer for reading a TOKEN_USER out of it */

  std::vector<uint8_t> buff(len);

  if (!GetTokenInformation(token.get(), TokenUser, buff.data(), len, &len)) {
    return Result::kFailure;  // LCOV_EXCL_LINE
  }

  wchar_t* raw_sid = nullptr;

  if (!ConvertSidToStringSidW(
          reinterpret_cast<const TOKEN_USER*>(buff.data())->User.Sid,
          &raw_sid)) {
    return Result::kFailure;  // LCOV_EXCL_LINE
  }

  const SidPtr sid(raw_sid);

  /* Protected DACL with one ACE granting full access to that SID alone */

  const std::wstring sddl = std::wstring(L"D:P(A;;FA;;;") + sid.get() + L")";

  PSECURITY_DESCRIPTOR raw_sd = nullptr;

  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
          sddl.c_str(), SDDL_REVISION_1, &raw_sd, nullptr)) {
    return Result::kFailure;  // LCOV_EXCL_LINE
  }

  sd.reset(raw_sd);

  return Result::kSuccess;
}

}  // namespace

int64_t GetFileSize(FILE* file) {
  struct _stat64 st = {};

  /* Fails if it isn't a regular file */

  if (_fstat64(_fileno(file), &st) != 0 || (st.st_mode & _S_IFMT) != _S_IFREG) {
    return -1;
  }

  /* Get the file size */

  if (_fseeki64(file, 0, SEEK_END)) {
    return -1;  // LCOV_EXCL_LINE
  }

  int64_t res = _ftelli64(file);

  /* Reset the cursor */

  if (_fseeki64(file, 0, SEEK_SET)) {
    return -1;  // LCOV_EXCL_LINE
  }

  return res;
}

bool FileExists(const std::string& path) {
  std::error_code ec;

  return std::filesystem::status(ToPath(path), ec).type() !=
         std::filesystem::file_type::not_found;
}

Result Random(uint8_t* dst, size_t size) {
  if (BCryptGenRandom(nullptr, dst, static_cast<ULONG>(size),
                      BCRYPT_USE_SYSTEM_PREFERRED_RNG)) {
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

  if (!MoveFileExW(src_path.c_str(), dst_path.c_str(),
                   MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
    return Result::kFailure;  // LCOV_EXCL_LINE
  }

  return Result::kSuccess;
}

RenameStatus RenameFileNoReplace(const std::string& src,
                                 const std::string& dst) {
  std::filesystem::path src_path = ToPath(src);
  std::filesystem::path dst_path = ToPath(dst);

  /* No MOVEFILE_REPLACE_EXISTING, so the move fails on a taken name */

  if (!MoveFileExW(src_path.c_str(), dst_path.c_str(),
                   MOVEFILE_WRITE_THROUGH)) {
    return CheckNameCollision(GetLastError()) ? RenameStatus::kExists
                                              : RenameStatus::kFailure;
  }

  return RenameStatus::kOk;
}

Result ResolvePath(const std::string& path, std::string& out) {
  std::error_code ec;

  const std::filesystem::path real =
      std::filesystem::canonical(ToPath(path), ec);

  if (ec) {
    return Result::kFailure;
  }

  /* u8string rather than string, which would narrow through the code page */

  const std::u8string text = real.u8string();

  out.assign(reinterpret_cast<const char*>(text.data()), text.size());

  return Result::kSuccess;
}

Result SyncFile(FILE* file) {
  /* Push the stdio buffer into the kernel */

  if (fflush(file)) {
    return Result::kFailure;
  }

  /* Get file handle */

  const intptr_t ptr = _get_osfhandle(_fileno(file));

  HANDLE handle =
      reinterpret_cast<HANDLE>(ptr);  // NOLINT(performance-no-int-to-ptr)

  if (handle == INVALID_HANDLE_VALUE) {
    return Result::kFailure;
  }

  /* Push the kernel's page cache onto the disk */

  if (!FlushFileBuffers(handle)) {
    return Result::kFailure;
  }

  return Result::kSuccess;
}

Result SyncDir(const std::string& path) {
  std::filesystem::path dir = ToPath(path).parent_path();

  HANDLE handle =
      CreateFileW(dir.empty() ? L"." : dir.c_str(), GENERIC_READ,
                  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                  nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);

  if (handle == INVALID_HANDLE_VALUE) {
    return Result::kFailure;
  }

  CloseHandle(handle);

  return Result::kSuccess;
}

void OpenFile(FILE** file, const std::string& path, const char* mode) {
  std::filesystem::path fs_path = ToPath(path);
  std::wstring wmode;

  for (const char* p = mode; *p; ++p) {
    wmode += static_cast<wchar_t>(*p);
  }

  _wfopen_s(file, fs_path.c_str(), wmode.c_str());
}

Result OpenRegularFile(FILE** file, const std::string& path) {
  *file = nullptr;

  std::filesystem::path fs_path = ToPath(path);

  HANDLE handle =
      CreateFileW(fs_path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                  OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

  if (handle == INVALID_HANDLE_VALUE) {
    return Result::kFailure;
  }

  BY_HANDLE_FILE_INFORMATION info = {};

  if (!GetFileInformationByHandle(handle, &info) ||
      (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 ||
      GetFileType(handle) != FILE_TYPE_DISK) {
    CloseHandle(handle);
    return Result::kFailure;
  }

  const int fd = _open_osfhandle(reinterpret_cast<intptr_t>(handle),
                                 _O_RDONLY | _O_BINARY);

  if (fd == -1) {
    CloseHandle(handle);
    return Result::kFailure;
  }

  *file = _fdopen(fd, "rb");

  if (*file == nullptr) {
    _close(fd);
    return Result::kFailure;
  }

  return Result::kSuccess;
}

Result OpenTempFile(FILE** file, std::string& path) {
  *file = nullptr;

  constexpr int kAttempts = 16;
  constexpr size_t kSuffixLen = 6;
  constexpr std::string_view kPool = "abcdefghijklmnopqrstuvwxyz0123456789";

  if (path.size() < kSuffixLen) {
    return Result::kFailure;  // LCOV_EXCL_LINE
  }

  const size_t suffix_pos = path.size() - kSuffixLen;

  /* Build the owner-only descriptor once, before any name is tried */

  SdPtr sd;

  if (MakeOwnerOnlyDescriptor(sd) == Result::kFailure) {
    return Result::kFailure;  // LCOV_EXCL_LINE
  }

  SECURITY_ATTRIBUTES attrs{ static_cast<DWORD>(sizeof(SECURITY_ATTRIBUTES)),
                             sd.get(), FALSE };

  for (int i = 0; i < kAttempts; i++) {
    for (size_t j = 0; j < kSuffixLen; j++) {
      uint32_t idx = 0;

      if (RandomRange(&idx, 0, static_cast<uint32_t>(kPool.size()) - 1) ==
          Result::kFailure) {
        return Result::kFailure;  // LCOV_EXCL_LINE
      }

      path[suffix_pos + j] = kPool[idx];
    }

    std::filesystem::path fs_path = ToPath(path);

    HANDLE handle = CreateFileW(
        fs_path.c_str(), GENERIC_WRITE, 0, &attrs, CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);

    if (handle == INVALID_HANDLE_VALUE) {
      /* Give up on a denied ACL, a missing directory or a full disk */

      if (!CheckNameCollision(GetLastError())) {
        return Result::kFailure;
      }

      continue;
    }

    const int fd = _open_osfhandle(reinterpret_cast<intptr_t>(handle),
                                   _O_WRONLY | _O_BINARY);

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

  return Result::kFailure;  // LCOV_EXCL_LINE
}
