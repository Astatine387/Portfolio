/**
 * @file    vault_header.h
 * @brief   Plaintext header of a vault file
 * @author  Astatine387
 */

#pragma once

#include <array>
#include <cstdint>
#include <span>

#include "common/constants.h"
#include "core/secure_key.h"

/**
 * @brief   Outcome of parsing or checking a vault header
 */
enum class HeaderStatus : std::uint8_t {
  kOk,
  kTooSmall,      // Fewer bytes than a header
  kBadMagic,      // Not written by this program
  kLegacyFormat,  // Written by a build that predates the key commitment
  kBadVersion,    // A format version this build does not know
  kBadParams,     // Argon2id parameters outside the accepted range
};

/**
 * @brief   Contents of the plaintext header
 */
struct VaultHeader {
  KdfParams params;  // Argon2id parameters the session key was derived under
  std::array<uint8_t, kSaltSize> salt{};  // Argon2id salt
  std::array<uint8_t, kCommitSize>
      commitment{};  // Key commitment of the master password
};

/**
 * @brief   Serialize a header into its on-disk form
 * @param   dst     Destination buffer
 * @param   header  Header to encode
 */
void SerializeHeader(std::span<uint8_t, kHeaderSize> dst,
                     const VaultHeader& header);

/**
 * @brief   Check and parse the leading bytes of a vault file
 * @param   src     Vault file bytes
 * @param   header  Destination header
 * @return  kOk when the header is usable, otherwise the reason it is not
 */
HeaderStatus ParseHeader(std::span<const uint8_t> src, VaultHeader& header);

/**
 * @brief   Check whether a header describes what this build can process
 * @param   header  Header to be checked
 * @return  kOk when every field is in range, kBadParams otherwise
 */
HeaderStatus ValidateHeader(const VaultHeader& header);

/**
 * @brief   Map a header status to a reportable message
 * @param   status  Status to describe
 * @return  Error message, or an empty string for kOk
 */
const char* HeaderErrorMessage(HeaderStatus status);
