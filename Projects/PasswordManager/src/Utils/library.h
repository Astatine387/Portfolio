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
 * @return	File size in bytes on success, -1 on failure
 */
int64_t GetFileSize(FILE *file);

/**
 * @brief	Generate CSPRN in given range
 * @param	min		Minimum value
 * @param	max		Maximum value
 * @return	CSPRN
 */
uint32_t RandomRange(uint32_t min, uint32_t max);

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
int Argon2id(uint8_t salt[], const char pw[], size_t plen, uint8_t key[]);

/**
 * @brief	Get the number of processors available
 * @return	Number of logical processors available
 */
int GetProcNum();

/**
 * @brief	Generates cryptographically secure pseudorandom bytes
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
 * @brief	Rename (move) a file, replacing destination if it exists
 * @param	src		Source file path
 * @param	dst		Destination file path
 * @return	0 on success, non-zero on failure
 */
int RenameFile(const QString &src, const QString &dst);

/**
 * @brief	Flush and sync file data to disk
 * @param	file	File pointer
 * @return	0 on success, non-zero on failure
 */
int SyncFile(FILE *file);

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
 * @brief	Shuffle an array
 * @param	arr		Array to shuffle
 * @param	size	Array size
 */
void Shuffle(uint8_t *arr, int size);

/**
 * @brief	Swap two data
 * @param	a	First datum
 * @param	b	Second datum
 */
void Swap(uint8_t *a, uint8_t *b);

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