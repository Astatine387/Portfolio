/**
 * @file	file_header.h
 * @brief	Header every encrypted file starts with
 * @author	Astatine387
 */

#pragma once

#include <array>
#include <cstdint>
#include <cstdio>

#include "common/constants.h"
#include "core/secure_key.h"

/**
 * @enum	HeaderStatus
 * @brief	Outcome of reading or checking an encrypted file header
 */
enum class HeaderStatus : std::uint8_t {
  kOk,
  kReadError,
  kBadMagic,
  kBadParams,
};

/**
 * @struct	FileHeader
 * @brief	Contents of the plaintext header
 */
struct FileHeader {
  KdfParams params;                       // Argon2id parameters the key was derived with
  std::array<uint8_t, kSaltSize> salt{};  // Key-derivation salt
  std::array<uint8_t, kIVSize> iv{};      // Initial vector for this file
};

/**
 * @brief	Read the header from the start of a file and check the magic number
 * @param	file	File pointer opened for reading
 * @param	header	Destination header, untouched unless kOk is returned
 * @return	kOk on success, kReadError on a short or unreadable file, kBadMagic on a foreign file
 */
HeaderStatus ReadHeader(FILE* file, FileHeader& header);

/**
 * @brief	Write a header to the current position of a file
 * @param	file	File pointer opened for writing
 * @param	header	Header to store
 * @return	kSuccess on success, kFailure on failure
 */
Result WriteHeader(FILE* file, const FileHeader& header);

/**
 * @brief	Check whether Argon2id parameters are within the range this build accepts
 * @param	params	Parameters read from a header
 * @return	kOk when every field is in range, kBadParams otherwise
 */
HeaderStatus ValidateKdfParams(const KdfParams& params);

/**
 * @brief	Map a header status to a reportable message
 * @param	status	Status to describe
 * @return	Message ending in a newline, or an empty string for kOk
 */
const char* HeaderErrorMessage(HeaderStatus status);
