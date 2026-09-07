/**
 * @file	secure_key.h
 * @brief	Move-only AES key held in libsodium-locked memory
 * @author	Astatine387
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

#include "common/constants.h"

/**
 * @struct	KdfParams
 * @brief	Argon2id key-derivation parameters
 *
 * Written into the file header, so decryption repeats the derivation with the parameters the file was made with rather
 * than whatever this build would choose today.
 */
struct KdfParams {
  uint32_t time_cost = kTimeCost;
  uint32_t mem_cost = kMemCost;
  uint32_t parallelism = kParallelism;
};

/**
 * @brief	Initialize libsodium and best-effort raise the memory-lock limit
 *
 * Idempotent and safe to call more than once
 *
 * Must run before any secure allocation or key derivation
 */
void InitCrypto();

class SecureKey;

/**
 * @brief	Derive a key from a password and salt using Argon2id
 * @param	pw		Password bytes
 * @param	salt	Key-derivation salt
 * @param	params	Argon2id parameters
 * @return	A SecureKey on success, std::nullopt on failure
 *
 * The only way to obtain a SecureKey. The constructor is private and this function is its friend, so a key cannot exist
 * except as the result of a derivation that filled it.
 */
[[nodiscard]] std::optional<SecureKey> DeriveKey(std::span<const char> pw, std::span<const uint8_t, kSaltSize> salt,
                                                 const KdfParams& params = {});

/**
 * @class   SecureKey
 * @brief   32-byte AES key and its key commitment, held in libsodium-locked memory
 */
class SecureKey {
 public:
  ~SecureKey();

  /* Move-only, and a moved-from key is left holding nothing. Two owners would mean two sodium_free calls on one buffer,
   * and a copy would be a second copy of the key in memory to keep track of. */

  SecureKey(const SecureKey&) = delete;             // Delete copy constructor
  SecureKey& operator=(const SecureKey&) = delete;  // Delete copy assignment operator

  SecureKey(SecureKey&& other) noexcept;
  SecureKey& operator=(SecureKey&& other) noexcept;

  /**
   * @brief   Expose the key bytes to the crypto layer
   * @return  View over the first kKeySize bytes of the kDerivedSize-byte derivation
   */
  [[nodiscard]] std::span<const uint8_t, kKeySize> Bytes() const;

  /**
   * @brief   Expose the key commitment to the header layer
   * @return	View over the last kCommitSize bytes of the kDerivedSize-byte derivation
   *
   * Public, and meant to be: it is written to the plaintext header, where the AEAD already covers it because the whole
   * header is the associated data of every chunk. It is not key material, and it reveals nothing about the half of the
   * derivation that is.
   */
  [[nodiscard]] std::span<const uint8_t, kCommitSize> Commitment() const;

  /**
   * @brief	Expose the salt this key was derived from
   * @return	View over the salt the derivation consumed
   *
   * Carried by the key rather than passed alongside it. A header describes the derivation a file was written under, so
   * letting a caller supply that description separately would let it describe a derivation other than the one that
   * produced the key it is written with. The two are one value here, and a mismatch has nowhere left to come from.
   */
  [[nodiscard]] std::span<const uint8_t, kSaltSize> Salt() const;

  /**
   * @brief   Expose the Argon2id parameters this key was derived with
   * @return  Parameters the derivation ran at
   */
  [[nodiscard]] const KdfParams& Params() const;

  /**
   * @brief   Constant-time comparison against a stored key commitment
   * @param   expected  Commitment read from a file header
   * @return  true if the commitment is the one this derivation produced
   */
  [[nodiscard]] bool CommitmentMatches(std::span<const uint8_t, kCommitSize> expected) const;

  /**
   * @brief	Constant-time comparison with another key
   * @param	other	Key to compare against
   * @return	true if the keys are equal
   */
  [[nodiscard]] bool ConstantTimeEquals(const SecureKey& other) const;

  friend std::optional<SecureKey> DeriveKey(std::span<const char> pw, std::span<const uint8_t, kSaltSize> salt,
                                            const KdfParams& params);

 private:
  SecureKey(uint8_t* data, std::span<const uint8_t, kSaltSize> salt, const KdfParams& params);

  uint8_t* data_ = nullptr;                // kDerivedSize bytes in sodium_malloc memory, released with sodium_free
  std::array<uint8_t, kSaltSize> salt_{};  // Salt this derivation consumed
  KdfParams params_;                       // Parameters this derivation ran at
};
