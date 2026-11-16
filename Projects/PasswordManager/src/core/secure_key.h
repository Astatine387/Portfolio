/**
 * @file    secure_key.h
 * @brief   Move-only AES key held in libsodium-locked memory
 * @author  Astatine387
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

#include "common/constants.h"

/**
 * @brief   Argon2id key-derivation parameters
 */
struct KdfParams {
  uint32_t time_cost = kTimeCost;
  uint32_t mem_cost = kMemCost;
  uint32_t parallelism = kParallelism;
};

/**
 * @brief   Initialize libsodium, best-effort raise the memory-lock limit and
 * refuse core dumps
 *
 * Must run before any secure allocation or key derivation. Idempotent and safe
 * to call multiple times.
 */
void InitCrypto();

class SecureKey;

/**
 * @brief   Derive a key from a password and salt using Argon2id
 * @param   pw      Password bytes
 * @param   salt    Key-derivation salt
 * @param   params  Argon2id parameters
 * @return  A SecureKey on success, std::nullopt on failure
 *
 * The only way to obtain a SecureKey
 */
[[nodiscard]] std::optional<SecureKey> DeriveKey(
    std::span<const char> pw, std::span<const uint8_t, kSaltSize> salt,
    const KdfParams& params = {});

/**
 * @brief   32-byte AES key and its key commitment
 */
class SecureKey {
 public:
  ~SecureKey();

  /* Move-only, and a moved-from key is left holding nothing */

  SecureKey(const SecureKey&) = delete;
  SecureKey& operator=(const SecureKey&) = delete;
  SecureKey(SecureKey&& other) noexcept;
  SecureKey& operator=(SecureKey&& other) noexcept;

  /**
   * @brief   Expose the key bytes to the crypto layer
   * @return  View over the first kKeySize bytes of the derivation
   */
  [[nodiscard]] std::span<const uint8_t, kKeySize> Bytes() const;

  /**
   * @brief   Expose the key commitment to the header layer
   * @return  View over the last kCommitSize bytes of the derivation
   */
  [[nodiscard]] std::span<const uint8_t, kCommitSize> Commitment() const;

  /**
   * @brief   Expose the salt this key was derived from
   * @return  View over the salt this key was derived from
   */
  [[nodiscard]] std::span<const uint8_t, kSaltSize> Salt() const;

  /**
   * @brief   Expose the Argon2id parameters this key was derived with
   * @return  Parameters this key was derived with
   */
  [[nodiscard]] const KdfParams& Params() const;

  /**
   * @brief   Constant-time comparison against a stored key commitment
   * @param   other  Commitment read from a file header
   * @return  true if the commitments are equal
   */
  [[nodiscard]] bool CommitmentMatches(
      std::span<const uint8_t, kCommitSize> other) const;

  /**
   * @brief   Constant-time comparison with another key, for test only
   * @param   other   Key to compare against
   * @return  true if the keys are equal
   */
  [[nodiscard]] bool ConstantTimeEquals(const SecureKey& other) const;

  friend std::optional<SecureKey> DeriveKey(
      std::span<const char> pw, std::span<const uint8_t, kSaltSize> salt,
      const KdfParams& params);

 private:
  SecureKey(uint8_t* data, std::span<const uint8_t, kSaltSize> salt,
            const KdfParams& params);

  uint8_t* data_ = nullptr;
  std::array<uint8_t, kSaltSize> salt_{};
  KdfParams params_;
};
