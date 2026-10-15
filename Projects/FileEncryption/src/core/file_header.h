/**
 * @file    file_header.h
 * @brief   Header of encrypted files
 * @author  Astatine387
 */

#pragma once

#include <array>
#include <cstdint>
#include <cstdio>
#include <span>

#include "common/constants.h"
#include "core/secure_key.h"

/**
 * @brief   Outcome of reading or checking an encrypted file header
 */
enum class HeaderStatus : std::uint8_t {
  kOk,
  kReadError,
  kBadMagic,
  kBadChunkSize,
  kBadParams,
};

/**
 * @brief   Contents of the plaintext header
 */
struct FileHeader {
  uint8_t chunk_log2 = kChunkSizeLog2;            // Base-2 log of chunk size
  KdfParams params;                               // Argon2id parameters
  std::array<uint8_t, kSaltSize> salt{};          // Argon2id salt
  std::array<uint8_t, kCommitSize> commitment{};  // Key commitment
};

/**
 * @brief   Serialize a header into its on-disk form
 * @param   dst     Destination buffer
 * @param   header  Source header
 */
void SerializeHeader(std::span<uint8_t, kHeaderSize> dst,
                     const FileHeader& header);

/**
 * @brief   Read, check and parse the header
 * @param   file    File pointer for reading
 * @param   header  Destination header
 * @return  kOk when the header is usable, otherwise the reason it is not
 */
HeaderStatus ReadHeader(FILE* file, FileHeader& header);

/**
 * @brief   Check whether a header describes what this build can process
 * @param   header  Header to be checked
 * @return  kOk when every field is in range, otherwise if any field is not
 */
HeaderStatus ValidateHeader(const FileHeader& header);

/**
 * @brief   Write a header
 * @param   file    File pointer for writing
 * @param   header  Source header
 * @return  kSuccess on success, kFailure on failure
 */
Result WriteHeader(FILE* file, const FileHeader& header);

/**
 * @brief   Map a header status to a reportable message
 * @param   status  Status to describe
 * @return  Error message, or an empty string for kOk
 */
const char* HeaderErrorMessage(HeaderStatus status);
