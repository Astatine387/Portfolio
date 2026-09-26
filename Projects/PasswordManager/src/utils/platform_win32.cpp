/**
 * @file	platform_win32.cpp
 * @brief	Implementation of utility functions for Windows
 * @author	Astatine387
 */

#include <windows.h>

#include <bcrypt.h>
#include <fcntl.h>
#include <io.h>
#include <sddl.h>

#include <array>
#include <filesystem>
#include <memory>
#include <system_error>
#include <vector>

#include "utils/platform.h"

namespace {

std::filesystem::path ToPath(const std::string& path) {
  return std::filesystem::path(std::u8string(reinterpret_cast<const char8_t*>(path.data()), path.size()));
}

bool CheckNameCollision(DWORD err) {
  return err == ERROR_FILE_EXISTS || err == ERROR_ALREADY_EXISTS;
}

/**
 * @struct  LocalGuard
 * @brief   Releases memory the security APIs allocated on the local heap
 *
 * Both the SID string and the security descriptor below are handed back as LocalAlloc memory that the caller owns,
 * and LocalFree is what releases either of them. An empty type rather than a function pointer, so that the pointers
 * wrapping it are the size of the pointer they hold.
 *
 * The Windows permission tests carry a copy of this deleter in win32_dacl.h rather than reaching for this one,
 * which they cannot: the anonymous namespace is what keeps it local to this file. Sharing it would mean either a
 * Win32 type in platform.h, with windows.h following it into every translation unit that includes that header, or
 * a public header of its own for three lines. The copy is deliberate.
 */
struct LocalGuard {
  void operator()(void* mem) const noexcept { LocalFree(mem); }
};

/**
 * @struct  HandleGuard
 * @brief   Closes a kernel handle
 */
struct HandleGuard {
  void operator()(HANDLE handle) const noexcept { CloseHandle(handle); }
};

/**
 * @brief   Owning handles for the three allocations an owner-only security descriptor is built out of
 *
 * Declared so that every way out of the build below releases what it has reached, without each early return having
 * to know which of the three are live at that point. HANDLE is a void pointer, which is why a token shares the
 * pointee type with a descriptor and differs only in how it is closed.
 */
using SdPtr = std::unique_ptr<void, LocalGuard>;
using SidPtr = std::unique_ptr<wchar_t, LocalGuard>;
using TokenPtr = std::unique_ptr<void, HandleGuard>;

/**
 * @brief   Build a security descriptor that grants the account this process runs as everything, and nobody else
 *          anything
 * @param   sd	Receives the descriptor on success, left as it was on failure
 * @return  kSuccess on success, kFailure on failure
 *
 * CreateFileW with no security attributes gives the new file a default security descriptor, and the DACL of that one
 * is whatever the parent directory offers for inheritance. A vault written into a directory other accounts can read
 * would be readable by them, so the descriptor a temporary is created under is built here rather than left to the
 * directory it happens to be created in.
 *
 * The SID is read from the process token and spelled into the ACE as itself, not through the CO (creator owner) or
 * OW (owner rights) aliases. Those resolve against whoever the owner of the file turns out to be, which is a
 * question about the file; what has to be named here is the account that is about to write a vault.
 */
Result MakeOwnerOnlyDescriptor(SdPtr& sd) {
  HANDLE raw_token = nullptr;

  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw_token)) {
    return Result::kFailure;  // LCOV_EXCL_LINE
  }

  const TokenPtr token(raw_token);

  /* A TokenUser answer is a TOKEN_USER followed by the variable-length SID its member points at, so its length is
   * not a constant and has to be asked for. The sizing call is the one that fails and reports the length, so a
   * sizing call that succeeds, or one that asks for less than the fixed part alone, is not an answer at all. */

  DWORD len = 0;

  if (GetTokenInformation(token.get(), TokenUser, nullptr, 0, &len) || len < sizeof(TOKEN_USER)) {
    return Result::kFailure;  // LCOV_EXCL_LINE
  }

  /* The buffer comes from operator new, which is aligned for every type of fundamental alignment, so reading a
   * TOKEN_USER back out of these bytes is as aligned as that type asks to be */

  std::vector<uint8_t> buff(len);

  if (!GetTokenInformation(token.get(), TokenUser, buff.data(), len, &len)) {
    return Result::kFailure;  // LCOV_EXCL_LINE
  }

  wchar_t* raw_sid = nullptr;

  if (!ConvertSidToStringSidW(reinterpret_cast<const TOKEN_USER*>(buff.data())->User.Sid, &raw_sid)) {
    return Result::kFailure;  // LCOV_EXCL_LINE
  }

  const SidPtr sid(raw_sid);

  /* D: opens the DACL, P protects it, and the single ACE allows FA to that one SID and carries no inheritance flags
   * of its own. An explicit DACL already keeps the parent directory from contributing at creation time; what P adds
   * is that a later change to the directory's own ACL cannot propagate into this file either. */

  const std::wstring sddl = std::wstring(L"D:P(A;;FA;;;") + sid.get() + L")";

  PSECURITY_DESCRIPTOR raw_sd = nullptr;

  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &raw_sd, nullptr)) {
    return Result::kFailure;  // LCOV_EXCL_LINE
  }

  sd.reset(raw_sd);

  return Result::kSuccess;
}

}  // namespace

int64_t GetFileSize(FILE* file) {
  if (_fseeki64(file, 0, SEEK_END)) {
    return -1;
  }

  int64_t size = _ftelli64(file);

  if (_fseeki64(file, 0, SEEK_SET)) {
    return -1;
  }

  return size;
}

bool FileExists(const std::string& path) {
  std::filesystem::path fs_path = ToPath(path);
  return std::filesystem::exists(fs_path);
}

Result Random(uint8_t* dst, size_t size) {
  if (BCryptGenRandom(nullptr, dst, static_cast<ULONG>(size), BCRYPT_USE_SYSTEM_PREFERRED_RNG)) {
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

  if (!MoveFileExW(src_path.c_str(), dst_path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
    return Result::kFailure;  // LCOV_EXCL_LINE
  }

  return Result::kSuccess;
}

RenameStatus RenameFileNoReplace(const std::string& src, const std::string& dst) {
  std::filesystem::path src_path = ToPath(src);
  std::filesystem::path dst_path = ToPath(dst);

  /* MOVEFILE_REPLACE_EXISTING is deliberately absent, so the move fails instead of overwriting an existing
   * destination. That refusal is the whole point: the move itself decides whether the name was free, so nothing can
   * appear at the destination between a separate existence test and the move that follows it. MOVEFILE_WRITE_THROUGH
   * is kept, so a published vault reaches the disk as durably as a replacing save does. */

  if (!MoveFileExW(src_path.c_str(), dst_path.c_str(), MOVEFILE_WRITE_THROUGH)) {
    return CheckNameCollision(GetLastError()) ? RenameStatus::kExists : RenameStatus::kFailure;
  }

  return RenameStatus::kOk;
}

Result ResolvePath(const std::string& path, std::string& out) {
  std::error_code ec;

  /* canonical rather than a read of the link's own target, because a target may be another link and may be relative to
   * the directory the link sits in. The error_code overload is the one that reports a path that does not resolve as a
   * failure instead of throwing, which this build has no way to catch. */

  const std::filesystem::path real = std::filesystem::canonical(ToPath(path), ec);

  if (ec) {
    return Result::kFailure;
  }

  /* u8string rather than string, which would narrow the wide path through the ANSI code page and lose whatever it
   * cannot spell. Every path the core holds is UTF-8, which is what ToPath reads on the way in. */

  const std::u8string text = real.u8string();

  out.assign(reinterpret_cast<const char*>(text.data()), text.size());

  return Result::kSuccess;
}

Result SyncFile(FILE* file) {
  if (fflush(file)) {
    return Result::kFailure;
  }

  const intptr_t ptr = _get_osfhandle(_fileno(file));

  HANDLE handle = reinterpret_cast<HANDLE>(ptr);  // NOLINT(performance-no-int-to-ptr)

  if (handle == INVALID_HANDLE_VALUE) {
    return Result::kFailure;
  }

  if (!FlushFileBuffers(handle)) {
    return Result::kFailure;
  }

  return Result::kSuccess;
}

Result SyncDir([[maybe_unused]] const std::string& path) {
  /* Windows has no directory-fsync; rename durability is handled by MOVEFILE_WRITE_THROUGH in RenameFile and
   * RenameFileNoReplace */
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

Result OpenTempFile(FILE** file, std::string& path) {
  *file = nullptr;

  constexpr int kAttempts = 16;
  constexpr size_t kSuffixLen = 6;
  constexpr std::string_view kPool = "abcdefghijklmnopqrstuvwxyz0123456789";

  if (path.size() < kSuffixLen) {
    return Result::kFailure;  // LCOV_EXCL_LINE
  }

  const size_t suffix_pos = path.size() - kSuffixLen;

  /* Build the descriptor before any name is tried. It describes the account this process runs as rather than the
   * file, so one descriptor serves every attempt; and a failure to build it is a failure of the whole call, taken
   * before a file exists. Falling back to no security attributes would create the file with the permissions of
   * whatever directory it sits in, which is exactly what this function promises not to do. */

  SdPtr sd;

  if (MakeOwnerOnlyDescriptor(sd) == Result::kFailure) {
    return Result::kFailure;  // LCOV_EXCL_LINE
  }

  SECURITY_ATTRIBUTES attrs{ static_cast<DWORD>(sizeof(SECURITY_ATTRIBUTES)), sd.get(), FALSE };

  for (int i = 0; i < kAttempts; i++) {
    for (size_t j = 0; j < kSuffixLen; j++) {
      uint32_t idx = 0;

      if (RandomRange(&idx, 0, static_cast<uint32_t>(kPool.size()) - 1) == Result::kFailure) {
        return Result::kFailure;  // LCOV_EXCL_LINE
      }

      path[suffix_pos + j] = kPool[idx];
    }

    std::filesystem::path fs_path = ToPath(path);

    HANDLE handle = CreateFileW(fs_path.c_str(), GENERIC_WRITE, 0, &attrs, CREATE_NEW,
                                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);

    if (handle == INVALID_HANDLE_VALUE) {
      /* Give up on a denied ACL, a missing directory or a full disk */

      if (!CheckNameCollision(GetLastError())) {
        return Result::kFailure;
      }

      continue;
    }

    const int fd = _open_osfhandle(reinterpret_cast<intptr_t>(handle), _O_WRONLY | _O_BINARY);

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
