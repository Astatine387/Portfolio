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
 * @enum	HeaderStatus
 * @brief	Outcome of reading or checking an encrypted file header
 *
 * The reason is kept rather than collapsed into a bool, because the failures do not mean the same thing
 * to whoever asked: a bad magic value says the file was never written by this program, while a bad chunk
 * size or bad parameters says it was, and this build will not read it.
 */
enum class HeaderStatus : std::uint8_t {
  kOk,
  kReadError,
  kBadMagic,
  kBadChunkSize,
  kBadParams,
};

/**
 * @struct	FileHeader
 * @brief	Contents of the plaintext header
 *
 * Readable by anyone and holding no secret: only what is needed to repeat the key derivation. It is not
 * unprotected for that, since every chunk is authenticated under these bytes, so a header edited after
 * the fact fails the tag of the whole file.
 */
struct FileHeader {
  uint8_t chunk_log2 = kChunkSizeLog2;    // Base-2 log of chunk size
  KdfParams params;                       // Argon2id parameters
  std::array<uint8_t, kSaltSize> salt{};  // Argon2id salt
};

/**
 * @brief   Serialize a header into its on-disk form
 * @param   dst     Destination buffer
 * @param   header  Header to encode
 *
 * These bytes are also the associated data of every chunk, which is why decryption re-serializes the
 * header it parsed instead of holding on to the buffer it read.
 */
void SerializeHeader(std::span<uint8_t, kHeaderSize> dst, const FileHeader& header);

/**
 * @brief   Read, check and parse the header
 * @param   file    File pointer for reading
 * @param   header  Destination header, untouched unless kOk is returned
 * @return  kOk when the header is usable, otherwise the reason it is not
 *
 * The single gate a header has to pass. The magic number is checked before any other byte is
 * trusted, then ValidateHeader is applied, so kOk means the caller may size buffers and derive
 * keys from the header without checking it again.
 */
HeaderStatus ReadHeader(FILE* file, FileHeader& header);

/**
 * @brief   Check whether a header describes what this build can process
 * @param   header  Header to be checked
 * @return  kOk when every field is in range, kBadChunkSize or kBadParams otherwise
 *
 * ReadHeader already applies this, so reading a file does not call it separately.
 *
 * The chunk size is checked before the key derivation parameters, because it is the field a
 * buffer is sized from and so deserves to be the reported reason when both are wrong.
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
