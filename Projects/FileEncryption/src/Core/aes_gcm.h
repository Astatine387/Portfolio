/**
 * @file	aes_gcm.h
 * @brief	AES-256-GCM file encryption/decryption engine
 * @author	Astatine387
 *
 * Contents:
 *	- Definition of AES_GCM class
 *	- Implementation of callback setting functions
 */

#pragma once

#include <openssl/evp.h>

#include <future>

#include "Common/constants.h"

/**
 * @class	AesGcm
 * @brief	AES-256-GCM file encryption/decryption engine
 */
class AesGcm {
 public:
  /* ==================================================
   * Constructor, destructor, operators
   * ================================================== */

  /**
   * @brief	Default constructor of AesGcm
   */
  AesGcm();

  /**
   * @brief	 Destructor of AesGcm
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
   * @brief		Decrypt a file
   * @param		src		Source file
   * @param		dst		Destination file
   * @param		pw		Password
   * @param		plen	Password length
   * @return    0 on success, 1 on failure
   */
  int Decrypt(FILE* src, FILE* dst, const char* pw, size_t plen);

  /**
   * @brief		Encrypt a file
   * @param		src		Source file
   * @param		dst		Destination file
   * @param		pw		Password
   * @param		plen	Password length
   * @return    0 on success, 1 on failure
   */
  int Encrypt(FILE* src, FILE* dst, const char* pw, size_t plen);

  /* ==================================================
   * Callback functions
   * ================================================== */

  /**
   * @brief		Callback function for error reporting
   * @param		msg		Error message string
   */
  using ErrorCallback = std::function<void(const char* msg)>;

  /**
   * @brief		Callback function for progress reporting
   * @param		perc		Current progress in percentage
   * @param		cancelled	Pointer of cancellation flag
   */
  using ProgressCallback = std::function<void(int perc, bool* cancelled)>;

  /**
   * @brief		Set error callback function
   * @param		ecb		Error callback function
   */
  void SetErrorCallback(ErrorCallback ecb) { ecb_ = ecb; }

  /**
   * @brief		Set progress callback function
   * @param		pcb		Progress callback function
   */
  void SetProgressCallback(ProgressCallback pcb) { pcb_ = pcb; }

 private:
  EVP_CIPHER_CTX* ctx_ = nullptr;  // OpenSSL encryption/decryption context

  FILE* src_file_ = nullptr;  // Source file
  FILE* dst_file_ = nullptr;  // Destination file

  ErrorCallback ecb_ = nullptr;     // Error reporting callback function
  ProgressCallback pcb_ = nullptr;  // Progress reporting callback function

  int64_t src_size_ = 0;      // Source file size
  int64_t progress_cur_ = 0;  // Current progress
  int64_t progress_max_ = 0;  // Total work for progress reporting

  uint8_t buff_[kBuffNum][kBuffSize][kBlockSize];  // Buffer
  uint8_t iv_[kIVSize];                            // Initial vector
  uint8_t key_[kKeySize];                          // Key derived from password
  uint8_t salt_[kSaltSize];                        // Key derivation salt
  uint8_t tag_[kTagSize];                          // Authentication tag read from file

  std::atomic<bool> cancelled_{ false };  // Is the program cancelled?
  std::future<int> write_res_;            // Asynchronous write result
  bool writing_ = false;                  // Is there currently ongoing asynchronous write?

  /* ==================================================
   * I/O helper functions
   * ================================================== */

  /**
   * @brief	    Read data from source file into buffer
   * @param	    buff	Destination buffer
   * @param	    size	Number of bytes to read
   * @return	0 on success, 1 on failure
   */
  int ReadFile(void* buff, int size);

  /**
   * @brief	    Write data from buffer to destination file
   * @param	    buff	Source buffer
   * @param	    size	Number of bytes to write
   * @return    0 on success, 1 on failure
   */
  int WriteFile(const void* buff, int size);

  /* ==================================================
   * Decryption functions
   * ================================================== */

  /**
   * @brief   Set up decryption context and reset file cursor
   * @return  0 on success, 1 on failure
   */
  int SetupDecryptCtx();

  /**
   * @brief   Run one decryption pass over the ciphertext
   * @param   mode   If true, write plaintext; if false, discard (verify only)
   * @return  0 on success, 1 on failure or cancellation
   */
  int DecryptPass(bool mode);

  /**
   * @brief	    Intialize decryption context
   * @param	    pw		Password
   * @param	    plen	Password length
   * @return	0 on success, 1 on failure
   */
  int DecryptInit(const char* pw, size_t plen);

  /**
   * @brief	    Decrypt buffer
   * @param	    src		Source buffer
   * @param	    dst		Destination buffer
   * @param	    srclen	Source buffer length
   * @return	0 on success, 1 on failure
   */
  int DecryptBuff(void* src, void* dst, int srclen);

  /**
   * @brief	Finialize decryption
   * @return	0 on success, 1 on failure
   */
  int DecryptFinal();

  /* ==================================================
   * Encryption functions
   * ================================================== */

  /**
   * @brief		Intialize encryption context
   * @param		pw		Password
   * @param		plen	Password length
   * @return	0 on success, 1 on failure
   */
  int EncryptInit(const char* pw, size_t plen);

  /**
   * @brief		Encrypt buffer
   * @param		src		Source buffer
   * @param		dst		Destination buffer
   * @param		srclen	Source buffer length
   * @return	0 on success, 1 on failure
   */
  int EncryptBuff(void* src, void* dst, int srclen);

  /**
   * @brief		Encrypt multiple blocks in a batch
   * @return	0 on success, 1 on failure
   */
  int EncryptBatch();

  /**
   * @brief		Encrypt remaining data smaller than buffer
   * @return	0 on success, 1 on failure
   */
  int EncryptRemain();

  /**
   * @brief		Finialize encryption
   * @return	0 on success, 1 on failure
   */
  int EncryptFinal();

  /**
   * @brief		Generate and write authentication tag
   * @return	0 on success, 1 on failure
   */
  int EncryptTag();

  /* ==================================================
   * Callback helper functions
   * ================================================== */

  /**
   * @brief		Report current progress via callback
   * @return	0 on continue, 1 on cancelled
   */
  int ReportProgress();

  /**
   * @brief		Report error via callback
   * @param		msg		Error message string
   */
  void ReportError(const char* msg);
};