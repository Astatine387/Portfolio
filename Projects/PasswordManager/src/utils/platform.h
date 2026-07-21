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
 * @brief	Generate CSPRN in given range
 * @param	dst		Output buffer for the generated number
 * @param	min		Minimum value
 * @param	max		Maximum value
 * @return	kSuccess on success, kFailure on failure
 */
Result RandomRange(uint32_t* dst, uint32_t min, uint32_t max);

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
 * @brief	Rename (move) a file, replacing destination if it exists
 * @param	src		Source file path
 * @param	dst		Destination file path
 * @return	kSuccess on success, kFailure on failure
 */
Result RenameFile(const std::string& src, const std::string& dst);

/**
 * @brief	Flush and sync file data to disk
 * @param	file	File pointer
 * @return	kSuccess on success, kFailure on failure
 */
Result SyncFile(FILE* file);

/**
 * @brief	Open a file
 * @param	file	File pointer
 * @param	path	File path
 * @param	mode	Mode
 */
void OpenFile(FILE** file, const std::string& path, const char* mode);

/**
 * @brief	Shuffle an array
 * @param	arr		Array to shuffle
 * @param	size	Array size
 * @return	kSuccess on success, kFailure on failure
 */
Result Shuffle(uint8_t* arr, int size);

/**
 * @brief	Swap two data
 * @param	a	First datum
 * @param	b	Second datum
 */
void Swap(uint8_t* a, uint8_t* b);