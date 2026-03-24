/**
 * @file	AES_GCM.h
 * @brief	AES-GCM encryption/decryption engine
 * @author	Astatine387
 */

#pragma once

#include "Common/constants.h"
#include <functional>
#include <future>
#include <openssl/evp.h>

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

	AES_GCM(const AES_GCM &) = delete;				// Delete copy constructor
	AES_GCM &operator=(const AES_GCM &) = delete;	// Delete copy assignment operator
	AES_GCM(AES_GCM &&) = delete;					// Delete move constructor
	AES_GCM &operator=(AES_GCM &&) = delete;		// Delete move assignment operator


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
	int decrypt(uint8_t *src, uint8_t *dst, size_t size, const char *pw, size_t plen);

	/**
	  * @brief		Encrypt a buffer
	  * @param		src			Source buffer
	  * @param		dst			Destination buffer
	  * @param		size		Source buffer size
	  * @param		pw			Password
	  * @param		plen		Password length
	  * @return		0 on success, 1 on failure
	  */
	int encrypt(uint8_t *src, uint8_t *dst, size_t size, const char *pw, size_t plen);


	/* ==================================================
	 * Callback functions
	 * ================================================== */

	/**
	 * @brief	Callback function for error reporting
	 * @param	errMsg	Error message string
	 */
	using ErrorCallback = std::function<void(const char *errMsg)>;

	/**
	 * @brief	Set error callback function
	 * @param	ecb		Error callback function
	 */
	void setErrorCb(ErrorCallback ecb) {
		this->ecb = ecb;
	}

private:
	EVP_CIPHER_CTX *ctx = nullptr;	// OpenSSL encryption/decryption context

	ErrorCallback ecb = nullptr;	// Error reporting callback function

	uint8_t iv[kIVSize];		// Initial vector
	uint8_t key[kKeySize];		// Key derived from password
	uint8_t salt[kSaltSize];	// Key derivation salt

	uint8_t *src = nullptr;		// Source buffer
	uint8_t *dst = nullptr;		// Destination buffer

	size_t srcCrs = 0;	// Current read position in buffer
	size_t dstCrs = 0;	// Current write position in buffer
	size_t size = 0;	// Source buffer size


	/* ==================================================
	 * Decryption functions
	 * ================================================== */

	/**
	 * @brief	Initialize decryption context
	 * @param	pw		Password
	 * @param	plen	Password length
	 * @return	0 on success, 1 on failure
	 */
	int decryptInit(const char *pw, size_t plen);

	/**
	 * @brief	Read and verify authentication tag
	 * @return	0 on success, 1 on failure
	 */
	int decryptTag();

	/**
	 * @brief	Decrypt buffer
	 * @return	0 on success, 1 on failure
	 */
	int decryptBuff();

	/**
	 * @brief	Finalize decryption
	 * @return	0 on success, 1 on failure
	 */
	int decryptFinal();


	/* ==================================================
	 * Encryption functions
	 * ================================================== */

	/**
	 * @brief	Initialize encryption context
	 * @param	pw		Password
	 * @param	plen	Password length
	 * @return	0 on success, 1 on failure
	 */
	int encryptInit(const char *pw, size_t plen);

	/**
	 * @brief	Encrypt buffer
	 * @return	0 on success, 1 on failure
	 */
	int encryptBuff();

	/**
	 * @brief	Finalize encryption
	 * @return	0 on success, 1 on failure
	 */
	int encryptFinal();

	/**
	 * @brief	Generate and write authentication tag
	 * @return	0 on success, 1 on failure
	 */
	int encryptTag();


	/* ==================================================
	 * Callback helper functions
	 * ================================================== */

	/**
	  * @brief	Report error via callback
	  * @param	msg		Error message string
	  */
	void reportError(const char *msg);
};