/**
 * @file    platform.h
 * @brief   Declaration of utility functions
 * @author  Astatine387
 */

#pragma once

#include <cstdint>
#include <cstdio>
#include <string>

#include "common/constants.h"

/**
 * @brief   Check whether a path is free
 * @param   path  File path
 * @return  false only when the path is known to hold nothing, true otherwise
 *
 * Never throws. A lookup that fails for any reason other than absence counts as
 * present, and a dangling symbolic link counts as free.
 */
bool FileExists(const std::string& path);

/**
 * @brief   Get the size of a file in bytes
 * @param   file  File pointer in read binary mode
 * @return  file size in bytes on success, -1 on failure
 */
int64_t GetFileSize(FILE* file);

/**
 * @brief   Generates cryptographically secure random bytes
 * @param   dst   Output buffer for random bytes
 * @param   size  Output buffer size
 * @return  kSuccess on success, kFailure on failure
 */
Result Random(uint8_t* dst, size_t size);

/**
 * @brief   Generate CSPRN in given range
 * @param   dst   Output buffer for the generated number
 * @param   min   Minimum value
 * @param   max   Maximum value
 * @return  kSuccess on success, kFailure on failure
 */
Result RandomRange(uint32_t* dst, uint32_t min, uint32_t max);

/**
 * @brief   Delete a file
 * @param   path  File path
 * @return  kSuccess on success, kFailure on failure
 */
Result RemoveFile(const std::string& path);

/**
 * @brief   Rename (move) a file, replacing destination if it exists
 * @param   src   Source file path
 * @param   dst   Destination file path
 * @return  kSuccess on success, kFailure on failure
 */
Result RenameFile(const std::string& src, const std::string& dst);

/**
 * @brief   Outcome of a move that refuses to replace its destination
 */
enum class RenameStatus : std::uint8_t {
  kOk,       // The move took the name
  kExists,   // Something already held the name, and it is left as it was
  kFailure,  // The move failed for any other reason
};

/**
 * @brief   Move a file onto a path, refusing to replace whatever is already
 * there
 * @param   src   Source file path
 * @param   dst   Destination file path
 * @return  kOk when the move took the name, kExists when it was taken, kFailure
 * on any other failure
 *
 * Does not overwrite an existing file, fails when the name already exists
 */
[[nodiscard]] RenameStatus RenameFileNoReplace(const std::string& src,
                                               const std::string& dst);

/**
 * @brief   Resolve a path to the file it leads to
 * @param   path  File path
 * @param   out   Receives the resolved path on success, left as it was on
 * failure
 * @return  kSuccess on success, kFailure when the path does not resolve
 *
 * Every symbolic link is followed, and the result is the absolute path of the
 * file itself. A dangling link does not resolve.
 */
[[nodiscard]] Result ResolvePath(const std::string& path, std::string& out);

/**
 * @brief   Flush and sync file data to disk
 * @param   file  File pointer
 * @return  kSuccess on success, kFailure on failure
 */
Result SyncFile(FILE* file);

/**
 * @brief   Flush the parent directory entry of a file to disk
 * @param   path  File path whose parent directory is synced
 * @return  kSuccess on success, kFailure on failure
 */
Result SyncDir(const std::string& path);

/**
 * @brief   Open a file
 * @param   file  File pointer
 * @param   path  File path
 * @param   mode  Mode
 */
void OpenFile(FILE** file, const std::string& path, const char* mode);

/**
 * @brief   Open an existing regular file for reading
 * @param   file  Opened stream on success, nullptr on failure
 * @param   path  File path
 * @return  kSuccess on success, kFailure on failure
 *
 * Never waits on a named pipe, and follows symbolic links
 */
[[nodiscard]] Result OpenRegularFile(FILE** file, const std::string& path);

/**
 * @brief   Create and open a private temporary file with a random name
 * @param   file  Opened stream on success, nullptr on failure
 * @param   path  In: template whose last six characters are "XXXXXX". Out: the
 * path actually created
 * @return  kSuccess on success, kFailure on failure
 *
 * The file is created owner-only
 */
[[nodiscard]] Result OpenTempFile(FILE** file, std::string& path);
