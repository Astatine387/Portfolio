/**
 * @file	platform.h
 * @brief	Declaration of utility functions
 * @author	Astatine387
 */

#pragma once

#include <cstdint>
#include <cstdio>
#include <string>

#include "common/constants.h"

/**
 * @brief   Check a file exists
 * @param   path	File path
 * @return	true if the file exists, false otherwise
 */
bool FileExists(const std::string& path);

/**
 * @brief   Get the size of a file in bytes
 * @param   file	File pointer in read binary mode
 * @return	file size in bytes on success, -1 on failure
 */
int64_t GetFileSize(FILE* file);

/**
 * @brief   Generates cryptographically secure random bytes
 * @param   dst		Output buffer for random bytes
 * @param   size	Output buffer size
 * @return  kSuccess on success, kFailure on failure
 */
Result Random(uint8_t* dst, size_t size);

/**
 * @brief   Generate CSPRN in given range
 * @param   dst		Output buffer for the generated number
 * @param   min		Minimum value
 * @param   max		Maximum value
 * @return	kSuccess on success, kFailure on failure
 */
Result RandomRange(uint32_t* dst, uint32_t min, uint32_t max);

/**
 * @brief   Delete a file
 * @param   path	File path
 * @return	kSuccess on success, kFailure on failure
 */
Result RemoveFile(const std::string& path);

/**
 * @brief   Rename (move) a file, replacing destination if it exists
 * @param   src		Source file path
 * @param   dst		Destination file path
 * @return	kSuccess on success, kFailure on failure
 */
Result RenameFile(const std::string& src, const std::string& dst);

/**
 * @enum	RenameStatus
 * @brief	Outcome of a move that refuses to replace its destination
 */
enum class RenameStatus : std::uint8_t {
  kOk,       // The move took the name
  kExists,   // Something already held the name, and it is left as it was
  kFailure,  // The move failed for any other reason
};

/**
 * @brief   Move a file onto a path, refusing to replace whatever is already there
 * @param   src		Source file path
 * @param   dst		Destination file path
 * @return	kOk when the move took the name, kExists when it was taken, kFailure on any other failure
 *
 * Refusing to overwrite is what makes this a create rather than a save: the move itself decides whether the name was
 * free, so nothing can appear at the destination between a separate existence test and the move that follows it.
 *
 * How that refusal is obtained differs by file system, so the Linux side tries three ways in turn and only falls
 * through on the errors that mean "this file system cannot do it". Whichever way is taken, the name is still won or
 * lost in one atomic step.
 */
[[nodiscard]] RenameStatus RenameFileNoReplace(const std::string& src, const std::string& dst);

/**
 * @brief   Resolve a path to the file it leads to
 * @param   path	File path
 * @param   out		Receives the resolved path on success, left as it was on failure
 * @return	kSuccess on success, kFailure when the path does not resolve
 *
 * Every component is followed, a chain of symbolic links included, and a relative link target is read against the
 * directory of the link that holds it. What comes back is the absolute path of the file itself, which is the path an
 * atomic replace has to act on: a rename onto a link's own path replaces the link and leaves the file behind it as it
 * was.
 *
 * A path that does not resolve is one whose file is not there, a dangling link among the ways of not being there, and
 * it fails rather than coming back as a path a caller might publish onto.
 */
[[nodiscard]] Result ResolvePath(const std::string& path, std::string& out);

/**
 * @brief   Flush and sync file data to disk
 * @param   file	File pointer
 * @return	kSuccess on success, kFailure on failure
 */
Result SyncFile(FILE* file);

/**
 * @brief   Flush the parent directory entry of a file to disk
 * @param   path	File path whose parent directory is synced
 * @return	kSuccess on success, kFailure on failure
 */
Result SyncDir(const std::string& path);

/**
 * @brief   Open a file
 * @param   file	File pointer
 * @param   path	File path
 * @param   mode	Mode
 */
void OpenFile(FILE** file, const std::string& path, const char* mode);

/**
 * @brief   Create and open a private temporary file with a random name
 * @param   file	Opened stream on success, nullptr on failure
 * @param   path	In: template whose last six characters are "XXXXXX". Out: the path actually created
 * @return	kSuccess on success, kFailure on failure
 *
 * The file is created owner-only and nothing here widens it, so an atomic replace that publishes this temporary
 * over an existing vault can tighten that vault's permissions but never loosen them.
 */
[[nodiscard]] Result OpenTempFile(FILE** file, std::string& path);
