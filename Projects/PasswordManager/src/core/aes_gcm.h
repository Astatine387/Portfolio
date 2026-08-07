/**
 * @file	aes_gcm.h
 * @brief	AES-GCM encryption/decryption engine
 * @author	Astatine387
 */

#pragma once

#include <openssl/evp.h>

#include <array>
#include <functional>
#include <future>
#include <span>

#include "common/constants.h"
#include "core/secure_key.h"

class AesGcm {
 public:
  /* ==================================================
   * Constructor, destructor, operators
   * ================================================== */

  /**
   * @brief	Default constructor of AesGcm class
   */
  AesGcm() = default;

  /**
   * @brief	Destructor of AesGcm class
   */
  ~AesGcm();

  AesGcm(const AesGcm&) = delete;             // Delete copy constructor
  AesGcm& operator=(const AesGcm&) = delete;  // Delete copy assignment operator
  AesGcm(AesGcm&&) = delete;                  // Delete move constructor
  AesGcm& operator=(AesGcm&&) = delete;       // Delete move assignment operator

  /* ==================================================
   * Interface functions
   * ================================================== */

  /**
   * @brief		Decrypt a buffer
   * @param		src		Source buffer
   * @param		dst		Destination buffer
   * @param		size	Source buffer size
   * @param		key		Session key
   * @return		kSuccess on success, kFailure on failure
   *
   * AES-GCM cannot authenticate the ciphertext until the whole message has been processed. On kFailure @p dst holds
   * unverified plaintext. The caller owns that buffer and must wipe it before doing anything else with it.
   */
  Result Decrypt(uint8_t* src, uint8_t* dst, size_t size, const SecureKey& key);

  /**
   * @brief		Encrypt a buffer
   * @param		src			Source buffer
   * @param		dst			Destination buffer
   * @param		size		Source buffer size
   * @param		key			Session key
   * @param		salt		Session salt written to the header
   * @return		kSuccess on success, kFailure on failure
   */
  Result Encrypt(uint8_t* src, uint8_t* dst, size_t size, const SecureKey& key,
                 std::span<const uint8_t, kSaltSize> salt);

  /* ==================================================
   * Callback functions
   * ================================================== */

  /**
   * @brief	Callback function for error reporting
   * @param	msg	Error message string
   */
  using ErrorCallback = std::function<void(const char* msg)>;

  /**
   * @brief	Set error callback function
   * @param	ecb		Error callback function
   */
  void SetErrorCallback(ErrorCallback ecb) { ecb_ = std::move(ecb); }

 private:
  EVP_CIPHER_CTX* ctx_ = nullptr;  // OpenSSL encryption/decryption context

  ErrorCallback ecb_ = nullptr;  // Error reporting callback function

  std::array<uint8_t, kIVSize> iv_{};    // Initial vector
  std::array<uint8_t, kTagSize> tag_{};  // Authentication tag read from buffer

  const SecureKey* key_ = nullptr;  // Session key for the current operation

  uint8_t* src_buff_ = nullptr;  // Source buffer
  uint8_t* dst_buff_ = nullptr;  // Destination buffer

  size_t dst_crs_ = 0;  // Current write position in buffer
  size_t size_ = 0;     // Source buffer size

  /* ==================================================
   * Decryption functions
   * ================================================== */

  /**
   * @brief	Read the IV and authentication tag from the buffer
   *
   * The salt was already consumed by the caller to derive the session key.
   */
  void DecryptInit();

  /**
   * @brief	Create the decryption context and set key, IV, and tag
   * @return	kSuccess on success, kFailure on failure
   */
  Result SetupDecryptCtx();

  /**
   * @brief	Decrypt a buffer
   * @param	src		Source buffer
   * @param	dst		Destination buffer
   * @param	len		Source buffer length
   * @return	kSuccess on success, kFailure on failure
   */
  Result DecryptBuff(const uint8_t* src, uint8_t* dst, int len);

  /**
   * @brief	Finalize decryption and verify the authentication tag
   * @return	kSuccess on success, kFailure on failure
   */
  Result DecryptFinal();

  /* ==================================================
   * Encryption functions
   * ================================================== */

  /**
   * @brief	Initialize the encryption context and write the header
   * @param	salt	Session salt written to the header
   * @return	kSuccess on success, kFailure on failure
   */
  Result EncryptInit(std::span<const uint8_t, kSaltSize> salt);

  /**
   * @brief	Encrypt buffer
   * @return	kSuccess on success, kFailure on failure
   */
  Result EncryptBuff();

  /**
   * @brief	Finalize encryption
   * @return	kSuccess on success, kFailure on failure
   */
  Result EncryptFinal();

  /**
   * @brief	Generate and write authentication tag
   * @return	kSuccess on success, kFailure on failure
   */
  Result EncryptTag();

  /* ==================================================
   * Callback helper functions
   * ================================================== */

  /**
   * @brief	Report error via callback
   * @param	msg		Error message string
   */
  void ReportError(const char* msg);
};
