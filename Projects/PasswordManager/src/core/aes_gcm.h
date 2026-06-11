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

#include "common/constants.h"

/**
 * @enum	DecryptMode
 * @brief	Whether a decryption pass verifies the tag or writes plaintext
 */
enum class DecryptMode : std::uint8_t {
  kVerify,
  kWrite,
};

class AesGcm {
 public:
  /* ==================================================
   * Constructor, destructor, operators
   * ================================================== */

  /**
   * @brief	Default constructor of AesGcm class
   */
  AesGcm();

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
   * @param		pw		Password
   * @param		plen	Password length
   * @return		kSuccess on success, kFailure on failure
   */
  Result Decrypt(uint8_t* src, uint8_t* dst, size_t size, const char* pw, size_t plen);

  /**
   * @brief		Encrypt a buffer
   * @param		src			Source buffer
   * @param		dst			Destination buffer
   * @param		size		Source buffer size
   * @param		pw			Password
   * @param		plen		Password length
   * @return		kSuccess on success, kFailure on failure
   */
  Result Encrypt(uint8_t* src, uint8_t* dst, size_t size, const char* pw, size_t plen);

  /* ==================================================
   * Callback functions
   * ================================================== */

  /**
   * @brief	Callback function for error reporting
   * @param	errMsg	Error message string
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

  std::array<uint8_t, kIVSize> iv_{};      // Initial vector
  std::array<uint8_t, kKeySize> key_{};    // Key derived from password
  std::array<uint8_t, kSaltSize> salt_{};  // Key derivation salt
  std::array<uint8_t, kTagSize> tag_{};    // Authentication tag read from buffer

  std::array<uint8_t, kBuffSize * kBlockSize> verify_buff_{};  // Scratch buffer for the verify pass

  uint8_t* src_buff_ = nullptr;  // Source buffer
  uint8_t* dst_buff_ = nullptr;  // Destination buffer

  size_t dst_crs_ = 0;  // Current write position in buffer
  size_t size_ = 0;     // Source buffer size

  /* ==================================================
   * Decryption functions
   * ================================================== */

  /**
   * @brief	Read salt, IV, and tag, then derive the key
   * @param	pw		Password
   * @param	plen	Password length
   * @return	kSuccess on success, kFailure on failure
   */
  Result DecryptInit(const char* pw, size_t plen);

  /**
   * @brief	Run one decryption pass over the ciphertext
   * @param	mode	kVerify to only check the tag, kWrite to emit plaintext
   * @return	kSuccess on success, kFailure on failure
   */
  Result DecryptBatch(DecryptMode mode);

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
   * @brief	Initialize encryption context
   * @param	pw		Password
   * @param	plen	Password length
   * @return	kSuccess on success, kFailure on failure
   */
  Result EncryptInit(const char* pw, size_t plen);

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