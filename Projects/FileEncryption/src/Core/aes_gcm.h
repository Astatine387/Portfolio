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

#include <array>
#include <cstdint>
#include <future>

#include "Common/constants.h"

enum class DecryptMode : std::uint8_t {
  kVerify,
  kWrite,
};

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
  void SetErrorCallback(ErrorCallback ecb) { ecb_ = std::move(ecb); }

  /**
   * @brief		Set progress callback function
   * @param		pcb		Progress callback function
   */
  void SetProgressCallback(ProgressCallback pcb) { pcb_ = std::move(pcb); }

 private:
  EVP_CIPHER_CTX* ctx_ = nullptr;  // OpenSSL encryption/decryption context

  FILE* src_file_ = nullptr;  // Source file
  FILE* dst_file_ = nullptr;  // Destination file

  ErrorCallback ecb_ = nullptr;     // Error reporting callback function
  ProgressCallback pcb_ = nullptr;  // Progress reporting callback function

  int64_t src_size_ = 0;      // Source file size
  int64_t progress_cur_ = 0;  // Current progress
  int64_t progress_max_ = 0;  // Total work for progress reporting

  std::array<std::array<std::array<uint8_t, kBlockSize>, kBuffSize>, kBuffNum> buff_{};  // Buffer
  std::array<uint8_t, kIVSize> iv_{};                                                    // Initial vector
  std::array<uint8_t, kKeySize> key_{};                                                  // Key derived from password
  std::array<uint8_t, kSaltSize> salt_{};                                                // Key derivation salt
  std::array<uint8_t, kTagSize> tag_{};  // Authentication tag read from file

  std::atomic<bool> cancelled_{ false };  // Is the program cancelled?
  std::future<int> write_res_;            // Asynchronous write result
  bool writing_ = false;                  // Whether there is ongoing asynchronous write
  bool key_locked_ = false;               // Whether the key buffer is locked in memory

  /* ==================================================
   * I/O helper functions
   * ================================================== */

  /**
   * @brief	    Read data from source file into buffer
   * @param	    buff	Destination buffer
   * @param	    size	Number of bytes to read
   * @return	0 on success, 1 on failure
   */
  int ReadFile(void* buff, size_t size);

  /**
   * @brief	    Write data from buffer to destination file
   * @param	    buff	Source buffer
   * @param	    size	Number of bytes to write
   * @return    0 on success, 1 on failure
   */
  int WriteFile(const void* buff, size_t size);

  /* ==================================================
   * Decryption functions
   * ================================================== */

  /**
   * @brief   Run one decryption pass over the ciphertext
   * @param   mode   True for write, false for verify
   * @return  0 on success, 1 on failure or cancellation
   */
  int DecryptBatch(DecryptMode mode);

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

  /**
   * @brief   Set up decryption context and reset file cursor
   * @return  0 on success, 1 on failure
   */
  int SetupDecryptCtx();

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