/**
 * @file	AES_GCM.h
 * @brief	AES-GCM encryption/decryption engine
 * @author	Astatine387
 */

#pragma once

#include <openssl/evp.h>

#include <functional>
#include <future>

#include "Common/constants.h"

class AES_GCM {
 public:
  /* ==================================================
   * Constructor, destructor, operators
   * ================================================== */

  /**
   * @brief	Default constructor of AES_GCM class
   */
  AES_GCM();

  /**
   * @brief	Destructor of AES_GCM class
   */
  ~AES_GCM();

  AES_GCM(const AES_GCM&) = delete;             // Delete copy constructor
  AES_GCM& operator=(const AES_GCM&) = delete;  // Delete copy assignment operator
  AES_GCM(AES_GCM&&) = delete;                  // Delete move constructor
  AES_GCM& operator=(AES_GCM&&) = delete;       // Delete move assignment operator

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
   * @return		0 on success, 1 on failure
   */
  int Decrypt(uint8_t* src, uint8_t* dst, size_t size, const char* pw, size_t plen);

  /**
   * @brief		Encrypt a buffer
   * @param		src			Source buffer
   * @param		dst			Destination buffer
   * @param		size		Source buffer size
   * @param		pw			Password
   * @param		plen		Password length
   * @return		0 on success, 1 on failure
   */
  int Encrypt(uint8_t* src, uint8_t* dst, size_t size, const char* pw, size_t plen);

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
  void SetErrorCallback(ErrorCallback ecb) { ecb_ = ecb; }

 private:
  EVP_CIPHER_CTX* ctx_ = nullptr;  // OpenSSL encryption/decryption context

  ErrorCallback ecb_ = nullptr;  // Error reporting callback function

  uint8_t iv_[kIVSize];      // Initial vector
  uint8_t key_[kKeySize];    // Key derived from password
  uint8_t salt_[kSaltSize];  // Key derivation salt

  uint8_t* src_buff_ = nullptr;  // Source buffer
  uint8_t* dst_buff_ = nullptr;  // Destination buffer

  size_t src_crs_ = 0;  // Current read position in buffer
  size_t dst_crs_ = 0;  // Current write position in buffer
  size_t size_ = 0;    // Source buffer size

  /* ==================================================
   * Decryption functions
   * ================================================== */

  /**
   * @brief	Initialize decryption context
   * @param	pw		Password
   * @param	plen	Password length
   * @return	0 on success, 1 on failure
   */
  int DecryptInit(const char* pw, size_t plen);

  /**
   * @brief	Read and verify authentication tag
   * @return	0 on success, 1 on failure
   */
  int DecryptTag();

  /**
   * @brief	Decrypt buffer
   * @return	0 on success, 1 on failure
   */
  int DecryptBuff();

  /**
   * @brief	Finalize decryption
   * @return	0 on success, 1 on failure
   */
  int DecryptFinal();

  /* ==================================================
   * Encryption functions
   * ================================================== */

  /**
   * @brief	Initialize encryption context
   * @param	pw		Password
   * @param	plen	Password length
   * @return	0 on success, 1 on failure
   */
  int EncryptInit(const char* pw, size_t plen);

  /**
   * @brief	Encrypt buffer
   * @return	0 on success, 1 on failure
   */
  int EncryptBuff();

  /**
   * @brief	Finalize encryption
   * @return	0 on success, 1 on failure
   */
  int EncryptFinal();

  /**
   * @brief	Generate and write authentication tag
   * @return	0 on success, 1 on failure
   */
  int EncryptTag();

  /* ==================================================
   * Callback helper functions
   * ================================================== */

  /**
   * @brief	Report error via callback
   * @param	msg		Error message string
   */
  void ReportError(const char* msg);
};