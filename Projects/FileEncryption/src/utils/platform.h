/**
 * @file    platform.h
 * @brief   Declaration of utility functions
 * @author  Astatine387
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
 * Does not overwrite an existing file, fails when the name already exists
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
 */
[[nodiscard]] Result OpenSourceFile(FILE** file, const std::string& path);

/**
 * @brief   Create and open a new file for writing, fail if it already exists
 * @param   file  Opened stream on success, nullptr on failure
 * @param   path  File path
 * @return  kSuccess on success, kFailure on failure
 */
[[nodiscard]] Result OpenNewFile(FILE** file, const std::string& path);
