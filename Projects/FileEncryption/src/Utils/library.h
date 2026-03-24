/**
 * @file	library.h
 * @brief	Declaration of utility functions
 * @author	Astatine387
 */

#pragma once

#include "Common/constants.h"
#include <cstdio>

class QString;

/**
 * @brief	Get the size of a file in bytes
 * @param	file	File pointer in read binary mode
 * @return	file size in bytes on success, -1 on failure
 */
int64_t GetFileSize(FILE *file);

/**
 * @brief	Check a file exists
 * @param	path	File path
 * @return	1 if file exists, 0 if file not exists
 */
bool FileExists(const QString &path);

/**
 * @brief	Derive a key using Argon2id
 * @param	salt	Input buffer for salt
 * @param	pw		Input buffer for password
 * @param	plen	Password length in bytes
 * @param	key		Output buffer for key
 * @return	0 on success, non-zero on failure
 */
int Argon2id(uint8_t *salt, const char *pw, size_t plen, uint8_t *key);

/**
 * @brief	Get the number of processors available
 * @return	Number of logical processors available
 */
int GetProcNum();

/**
 * @brief	Generates cryptographically secure random bytes
 * @param	dst		Output buffer for random bytes
 * @param	size	Output buffer size
 * @return	0 on success, non-zero on failure
 */
int Random(uint8_t *dst, size_t size);

/**
 * @brief	Delete a file
 * @param	path	File path
 * @return	0 on success, non-zero on failure
 */
int RemoveFile(const QString &path);

/**
 * @brief	Move file pointer to specific position
 * @param	file	File pointer
 * @param	dist	Distance from reference point
 * @param	ref		Reference point
 * @return	0 on success, non-zero on failure
 */
int Seek(FILE *file, int64_t dist, int ref);

/**
 * @brief	Lock memory space so that it cannot be swapped
 * @param	buff	Buffer to lock
 * @param	size	Buffer size in bytes
 */
void Lock(void *ptr, size_t size);

/**
 * @brief	Open a file
 * @param	file	File pointer
 * @param	path	File path
 * @param	mode	Mode
 */
void OpenFile(FILE **file, const QString &path, const char *mode);

/**
 * @brief	Unlock memory space so that it can be swapped
 * @param	buff	Buffer to unlock
 * @param	size	Buffer size in bytes
 */
void Unlock(void *ptr, size_t size);

/**
 * @brief	Securely wipe data in memory
 * @param	buff	Buffer to wipe
 * @param	size	Buffer size in bytes
 */
void Wipe(void *buff, size_t size);