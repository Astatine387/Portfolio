/**
 * @file	platform.h
 * @brief	Declaration of utility functions
 * @author	Astatine387
 */

#pragma once

#include <cstdio>
#include <string>

#include "common/constants.h"

/**
 * @brief	Get the size of a file in bytes
 * @param	file	File pointer in read binary mode
 * @return	file size in bytes on success, -1 on failure
 */
int64_t GetFileSize(FILE* file);

/**
 * @brief	Check a file exists
 * @param	path	File path
 * @return	1 if file exists, 0 if file not exists
 */
bool FileExists(const std::string& path);

/**
 * @brief	Generates cryptographically secure random bytes
 * @param	dst		Output buffer for random bytes
 * @param	size	Output buffer size
 * @return	kSuccess on success, kFailure on failure
 */
Result Random(uint8_t* dst, size_t size);

/**
 * @brief	Delete a file
 * @param	path	File path
 * @return	kSuccess on success, kFailure on failure
 */
Result RemoveFile(const std::string& path);

/**
 * @brief	Move file pointer to specific position
 * @param	file	File pointer
 * @param	dist	Distance from reference point
 * @param	ref		Reference point
 * @return	kSuccess on success, kFailure on failure
 */
Result Seek(FILE* file, int64_t dist, int ref);

/**
 * @brief	Open a file
 * @param	file	File pointer
 * @param	path	File path
 * @param	mode	Mode
 */
void OpenFile(FILE** file, const std::string& path, const char* mode);