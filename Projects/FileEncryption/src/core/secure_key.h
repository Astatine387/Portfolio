/**
 * @file	secure_key.h
 * @brief	Move-only AES key held in libsodium-locked memory
 * @author	Astatine387
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

#include "common/constants.h"

/**
 * @struct	KdfParams
 * @brief	Argon2id key-derivation parameters
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
 */
[[nodiscard]] std::optional<SecureKey> DeriveKey(std::span<const char> pw, std::span<const uint8_t, kSaltSize> salt,
                                                 const KdfParams& params = {});

/**
 * @class	SecureKey
 * @brief	32-byte AES key held in libsodium-locked memory
 */
class SecureKey {
 public:
  ~SecureKey();

  SecureKey(const SecureKey&) = delete;             // Delete copy constructor
  SecureKey& operator=(const SecureKey&) = delete;  // Delete copy assignment operator

  SecureKey(SecureKey&& other) noexcept;
  SecureKey& operator=(SecureKey&& other) noexcept;

  /**
   * @brief	Expose the key bytes to the crypto layer
   * @return	View over the key bytes
   */
  [[nodiscard]] std::span<const uint8_t, kKeySize> Bytes() const;

  /**
   * @brief	Constant-time comparison with another key
   * @param	other	Key to compare against
   * @return	true if the keys are equal
   */
  [[nodiscard]] bool ConstantTimeEquals(const SecureKey& other) const;

  friend std::optional<SecureKey> DeriveKey(std::span<const char> pw, std::span<const uint8_t, kSaltSize> salt,
                                            const KdfParams& params);

 private:
  explicit SecureKey(uint8_t* data) : data_(data) {}

  uint8_t* data_ = nullptr;  // kKeySize bytes in sodium_malloc memory
};
