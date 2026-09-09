/**
 * @file	vault_header.h
 * @brief	Plaintext header of a vault file
 * @author	Astatine387
 */

#pragma once

#include <array>
#include <cstdint>
#include <span>

#include "common/constants.h"
#include "core/secure_key.h"

/**
 * @enum	HeaderStatus
 * @brief	Outcome of parsing or checking a vault header
 *
 * The reason is kept rather than collapsed into a bool, because the failures do not mean the same thing to whoever
 * asked: a bad magic value says the file was never written by this program at all, the legacy value says it was but
 * by a build that predates the commitment, and out-of-range parameters say this build will not derive a key under
 * what the file asks for.
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
 * @struct	VaultHeader
 * @brief	Contents of the plaintext header
 *
 * Readable by anyone and holding no secret: what is needed to repeat the key derivation, and the commitment that says
 * which derivation was the right one. Being plaintext does not make it unprotected, since the whole header is the
 * associated data of the vault's single GCM pass, so a header edited after the fact fails the tag.
 */
struct VaultHeader {
  KdfParams params;                               // Argon2id parameters the session key was derived under
  std::array<uint8_t, kSaltSize> salt{};          // Argon2id salt
  std::array<uint8_t, kCommitSize> commitment{};  // Key commitment of the master password the vault was written with
};

/**
 * @brief	Serialize a header into its on-disk form
 * @param	dst		Destination buffer, exactly kHeaderSize bytes
 * @param	header	Header to encode
 *
 * The magic number and the format version are this build's own and are not carried in @p header, since a vault is
 * only ever written in the format this build writes.
 */
void SerializeHeader(std::span<uint8_t, kHeaderSize> dst, const VaultHeader& header);

/**
 * @brief	Check and parse the leading bytes of a vault file
 * @param	src		Vault file bytes, of which only the first kHeaderSize are read
 * @param	header	Destination header, left untouched unless kOk is returned
 * @return	kOk when the header is usable, otherwise the reason it is not
 *
 * The single gate a header has to pass. Size, magic, version and parameter ranges are checked in that order, so kOk
 * means the caller may size buffers and derive keys from the header without checking any of it again.
 */
HeaderStatus ParseHeader(std::span<const uint8_t> src, VaultHeader& header);

/**
 * @brief	Check whether a header describes what this build can process
 * @param	header	Header to be checked
 * @return	kOk when every field is in range, kBadParams otherwise
 *
 * ParseHeader already applies this, so parsing a header does not call it separately.
 */
HeaderStatus ValidateHeader(const VaultHeader& header);

/**
 * @brief	Map a header status to a reportable message
 * @param	status	Status to describe
 * @return	Error message, or an empty string for kOk
 */
const char* HeaderErrorMessage(HeaderStatus status);
