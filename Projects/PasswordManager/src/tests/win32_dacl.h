/**
 * @file    win32_dacl.h
 * @brief   Shared Windows DACL helpers for the file permission tests
 * @author  Astatine387
 */

#pragma once

#include <windows.h>

#include <aclapi.h>
#include <gtest/gtest.h>
#include <sddl.h>

#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

/* What these helpers read is the Windows half of the promise OpenTempFile makes: the file it creates is reachable by
 * the account that created it and by nobody else. On POSIX that is one mode word and a stat call away, which is why
 * the tests there need no helper; here it is a security descriptor, a DACL, an ACE and a SID, which is enough work
 * to be worth stating once for both the OpenTempFile tests and the vault ones.
 *
 * The LocalFree deleter is written out again here rather than shared with platform_win32.cpp, which keeps its own in
 * an anonymous namespace. A test that borrowed the implementation's idea of how this memory is released would no
 * longer be reading the file the way anything outside the program reads it.
 */

/**
 * @struct  LocalGuard
 * @brief   Releases memory the security APIs allocated on the local heap
 */
struct LocalGuard {
  void operator()(void* mem) const noexcept { LocalFree(mem); }
};

using LocalPtr = std::unique_ptr<void, LocalGuard>;

/* FILE_ALL_ACCESS is a signed constant in the platform headers while the mask inside an ACE is not, so the
 * comparison below is made on one type rather than left to the conversions the two would otherwise go through */

constexpr ACCESS_MASK kFullFileAccess = static_cast<ACCESS_MASK>(FILE_ALL_ACCESS);

/**
 * @brief   Widen a path the way the platform layer widens one
 * @param   path	Path in UTF-8
 * @return  Same path as a wide string
 */
inline std::wstring ToWidePath(const std::string& path) {
  return std::filesystem::path(std::u8string(reinterpret_cast<const char8_t*>(path.data()), path.size())).wstring();
}

/**
 * @brief   Narrow a string one of the security APIs returned
 * @param   wide	Wide string
 * @return  Same text as a narrow string
 *
 * SDDL text and SID strings are spelled out of ASCII alone, so narrowing one character at a time loses nothing, and
 * a narrow string is what a gtest message can carry.
 */
inline std::string ToNarrow(const wchar_t* wide) {
  std::string str;

  for (const wchar_t* p = wide; *p; ++p) {
    str += static_cast<char>(*p);
  }

  return str;
}

/**
 * @brief   SID of the account the calling process runs as
 * @return  SID in string form, empty on failure
 */
inline std::string CurrentUserSid() {
  HANDLE token = nullptr;

  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
    return {};
  }

  DWORD len = 0;

  /* The sizing call is the one that fails and reports the length a TokenUser answer needs */

  GetTokenInformation(token, TokenUser, nullptr, 0, &len);

  std::vector<uint8_t> buff(len);

  const bool ok = len >= sizeof(TOKEN_USER) && GetTokenInformation(token, TokenUser, buff.data(), len, &len) != FALSE;

  CloseHandle(token);

  if (!ok) {
    return {};
  }

  wchar_t* raw_sid = nullptr;

  if (!ConvertSidToStringSidW(reinterpret_cast<const TOKEN_USER*>(buff.data())->User.Sid, &raw_sid)) {
    return {};
  }

  const LocalPtr sid(raw_sid);

  return ToNarrow(raw_sid);
}

/**
 * @brief   SDDL text of the DACL a security descriptor carries
 * @param   sd	Security descriptor to describe
 * @return  SDDL string, or a placeholder if the descriptor could not be converted
 */
inline std::string DescriptorToSddl(PSECURITY_DESCRIPTOR sd) {
  wchar_t* raw_sddl = nullptr;

  if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &raw_sddl,
                                                            nullptr)) {
    return "<not convertible to SDDL>";
  }

  const LocalPtr sddl(raw_sddl);

  return ToNarrow(raw_sddl);
}

/**
 * @brief   Create a directory that hands every account an inheritable full-access ACE
 * @param   path	Directory path to create
 * @return  Success, or failure naming the call that did not go through
 *
 * OICI makes the ACE inheritable by both the files and the directories created inside, which is the state a default
 * security descriptor picks up and keeps. A file created in here with no descriptor of its own therefore comes out
 * readable by everybody, and that is the condition these tests hold the vault path against. S-1-1-0 is Everyone,
 * written as the SID rather than as the WD alias so that what is being granted is visible here.
 */
inline testing::AssertionResult MakeWorldAccessibleDir(const std::string& path) {
  PSECURITY_DESCRIPTOR raw_sd = nullptr;

  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(A;OICI;FA;;;S-1-1-0)", SDDL_REVISION_1, &raw_sd,
                                                            nullptr)) {
    return testing::AssertionFailure() << "ConvertStringSecurityDescriptorToSecurityDescriptorW failed with "
                                       << GetLastError();
  }

  const LocalPtr sd(raw_sd);

  SECURITY_ATTRIBUTES attrs{ static_cast<DWORD>(sizeof(SECURITY_ATTRIBUTES)), raw_sd, FALSE };

  if (!CreateDirectoryW(ToWidePath(path).c_str(), &attrs)) {
    return testing::AssertionFailure() << "CreateDirectoryW(" << path << ") failed with " << GetLastError();
  }

  return testing::AssertionSuccess();
}

/**
 * @brief   Check a file is reachable by the calling process user alone
 * @param   path	Path of the file to inspect
 * @return  Success if the DACL is the protected single-ACE one, failure naming what did not match
 *
 * Four things together say owner-only, and any one of them missing does not: the DACL is present at all, since a
 * descriptor without one grants everyone everything; it is protected, so neither the parent directory at creation
 * time nor a later propagation over that directory can add to it; it holds exactly one ACE, which allows rather than
 * denies and carries no inheritance flags; and that ACE names the account this process runs as, with the full file
 * mask and nothing less.
 *
 * The SDDL text of the descriptor goes into the log on the way past, so a CI run records the permissions it actually
 * observed rather than only whether they satisfied this function.
 *
 * The file has to be closed before this is called. OpenTempFile opens its handle with no sharing at all, so a second
 * open by name, which is what reading the security of a path amounts to, is refused for as long as that handle is
 * alive.
 */
inline testing::AssertionResult CheckOwnerOnlyDacl(const std::string& path) {
  PSECURITY_DESCRIPTOR raw_sd = nullptr;
  PACL dacl = nullptr;

  const DWORD err = GetNamedSecurityInfoW(ToWidePath(path).c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr,
                                          nullptr, &dacl, nullptr, &raw_sd);

  if (err != ERROR_SUCCESS) {
    return testing::AssertionFailure() << "GetNamedSecurityInfoW(" << path << ") failed with " << err;
  }

  const LocalPtr sd(raw_sd);
  const std::string sddl = DescriptorToSddl(raw_sd);

  GTEST_LOG_(INFO) << "DACL of " << path << ": " << sddl;

  auto fail = [&path, &sddl]() { return testing::AssertionFailure() << path << " (SDDL " << sddl << "): "; };

  if (dacl == nullptr) {
    return fail() << "no DACL at all, which grants every account everything";
  }

  SECURITY_DESCRIPTOR_CONTROL control = 0;
  DWORD revision = 0;

  if (!GetSecurityDescriptorControl(raw_sd, &control, &revision)) {
    return fail() << "GetSecurityDescriptorControl failed with " << GetLastError();
  }

  if ((control & SE_DACL_PROTECTED) == 0) {
    return fail() << "the DACL is not protected, so the parent directory can still add to it";
  }

  ACL_SIZE_INFORMATION info = {};

  if (!GetAclInformation(dacl, &info, static_cast<DWORD>(sizeof(info)), AclSizeInformation)) {
    return fail() << "GetAclInformation failed with " << GetLastError();
  }

  if (info.AceCount != 1u) {
    return fail() << "the DACL holds " << info.AceCount << " ACEs, and one account needs exactly one";
  }

  void* raw_ace = nullptr;

  if (!GetAce(dacl, 0, &raw_ace)) {
    return fail() << "GetAce failed with " << GetLastError();
  }

  ACCESS_ALLOWED_ACE* ace = static_cast<ACCESS_ALLOWED_ACE*>(raw_ace);

  if (ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE) {
    return fail() << "the single ACE is of type " << static_cast<unsigned>(ace->Header.AceType)
                  << " rather than an allow ACE";
  }

  if (ace->Header.AceFlags != 0) {
    return fail() << "the single ACE carries flags " << static_cast<unsigned>(ace->Header.AceFlags)
                  << " rather than none";
  }

  if (ace->Mask != kFullFileAccess) {
    return fail() << "the single ACE grants mask " << ace->Mask << " rather than FILE_ALL_ACCESS (" << kFullFileAccess
                  << ")";
  }

  wchar_t* raw_sid = nullptr;

  if (!ConvertSidToStringSidW(&ace->SidStart, &raw_sid)) {
    return fail() << "the SID of the single ACE could not be read: " << GetLastError();
  }

  const LocalPtr ace_sid(raw_sid);
  const std::string user_sid = CurrentUserSid();

  if (user_sid.empty()) {
    return fail() << "the SID of the current process token could not be read";
  }

  if (ToNarrow(raw_sid) != user_sid) {
    return fail() << "the single ACE names " << ToNarrow(raw_sid) << " rather than the token user " << user_sid;
  }

  return testing::AssertionSuccess();
}
