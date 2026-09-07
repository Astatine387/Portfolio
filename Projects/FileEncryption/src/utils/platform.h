/**
 * @file	platform.h
 * @brief	Declaration of utility functions
 * @author	Astatine387
 *
 * One set of declarations, two implementations: platform_linux.cpp and platform_win32.cpp, chosen by
 * CMake. Everything the program does to a file goes through here, so the two builds differ in those two
 * files and nowhere else.
 */

#pragma once

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
 *
 * A stream on anything other than a regular file is a failure rather than a size. A procfs entry
 * reports zero and a character device reports whatever its driver feels like, and either one read as a
 * size would turn a source with contents into an empty one. OpenSourceFile refuses those at the open,
 * and this is the second place that refuses them, for a stream that arrived some other way.
 */
int64_t GetFileSize(FILE* file);

/**
 * @brief   Generates cryptographically secure random bytes
 * @param   dst		Output buffer for random bytes
 * @param   size	Output buffer size
 * @return	kSuccess on success, kFailure on failure
 */
Result Random(uint8_t* dst, size_t size);

/**
 * @brief   Delete a file
 * @param   path	File path
 * @return	kSuccess on success, kFailure on failure
 */
Result RemoveFile(const std::string& path);

/**
 * @brief   Move a file onto a path
 * @param   src   Source file path
 * @param   dst   Destination file path
 * @return  kSuccess on success, kFailure on failure
 *
 * This doesn't overwrite an existing file. Refusing to is what makes the publish step safe: the move
 * itself decides whether the name was free, so nothing can appear at the destination between a separate
 * existence test and the move that follows it.
 *
 * How that refusal is obtained differs by file system, so the Linux side tries three ways in turn and
 * only falls through on the errors that mean "this file system cannot do it". Whichever way is taken,
 * the name is still won or lost in one atomic step.
 */
Result RenameFile(const std::string& src, const std::string& dst);

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
 *
 * SyncFile is only half of it. The entry that names the file is a write of its own, and a file whose
 * contents reached the disk under a name that did not is still lost.
 */
Result SyncDir(const std::string& path);

/**
 * @brief   Move file pointer to specific position
 * @param   file	File pointer
 * @param   dist	Distance from reference point
 * @param   ref		Reference point
 * @return  kSuccess on success, kFailure on failure
 */
Result Seek(FILE* file, int64_t dist, int ref);

/**
 * @brief   Open a file
 * @param   file	File pointer
 * @param   path	File path
 * @param   mode  Mode
 */
void OpenFile(FILE** file, const std::string& path, const char* mode);

/**
 * @brief   Open an existing regular file for reading
 * @param   file  Opened stream on success, nullptr on failure
 * @param   path  File path
 * @return  kSuccess on success, kFailure on failure
 *
 * The read end of what OpenNewFile does for the write end, and held to the same standard. A plain fopen
 * accepts a directory, a symbolic link and a procfs entry alike, and the last of those reports a size of
 * zero, which would be encrypted into an empty file and reported as a success. The type is therefore
 * decided from the descriptor that was opened, not from the path, so the answer cannot change between
 * the check and the read.
 */
[[nodiscard]] Result OpenSourceFile(FILE** file, const std::string& path);

/**
 * @brief   Create and open a new file for writing, fail if it already exists
 * @param   file  Opened stream on success, nullptr on failure
 * @param   path  File path
 * @return  kSuccess on success, kFailure on failure
 *
 * Creating exclusively rather than testing first, so the file system is the one deciding the name was
 * free and nothing can take it in between.
 */
[[nodiscard]] Result OpenNewFile(FILE** file, const std::string& path);
