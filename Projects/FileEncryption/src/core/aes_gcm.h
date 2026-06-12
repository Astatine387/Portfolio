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
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <mutex>
#include <thread>

#include "common/constants.h"

enum class DecryptMode : std::uint8_t {
  kVerify,
  kWrite,
};

/**
 * @enum	Progress
 * @brief	Whether processing should continue or was cancelled by the user
 */
enum class Progress : std::uint8_t {
  kContinue,
  kCancelled,
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
   * @return    kSuccess on success, kFailure on failure
   */
  Result Decrypt(FILE* src, FILE* dst, const char* pw, size_t plen);

  /**
   * @brief		Encrypt a file
   * @param		src		Source file
   * @param		dst		Destination file
   * @param		pw		Password
   * @param		plen	Password length
   * @return    kSuccess on success, kFailure on failure
   */
  Result Encrypt(FILE* src, FILE* dst, const char* pw, size_t plen);

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
  std::mutex error_mtx_;            // Serializes error callback calls from the read and write threads

  int64_t src_size_ = 0;      // Source file size
  int64_t progress_cur_ = 0;  // Current progress
  int64_t progress_max_ = 0;  // Total work for progress reporting

  std::array<std::array<std::array<uint8_t, kBlockSize>, kBuffSize>, kBuffNum> buff_{};  // Buffer
  std::array<uint8_t, kIVSize> iv_{};                                                    // Initial vector
  std::array<uint8_t, kKeySize> key_{};                                                  // Key derived from password
  std::array<uint8_t, kSaltSize> salt_{};                                                // Key derivation salt
  std::array<uint8_t, kTagSize> tag_{};  // Authentication tag read from file

  std::thread writer_;                      // Long-lived asynchronous write worker
  std::mutex write_mtx_;                    // Guards the write hand-off state below
  std::condition_variable write_cv_;        // Signals job-ready and job-done transitions
  const void* write_buff_ = nullptr;        // Buffer queued for writing
  size_t write_size_ = 0;                   // Number of bytes queued for writing
  bool write_pending_ = false;              // Whether a write job is queued or in progress
  bool writer_stop_ = false;                // Whether the writer thread should exit
  Result write_result_ = Result::kSuccess;  // Result of the most recent write
  bool key_locked_ = false;                 // Whether the key buffer is locked in memory

  /* ==================================================
   * I/O helper functions
   * ================================================== */

  /**
   * @brief	    Read data from source file into buffer
   * @param	    buff	Destination buffer
   * @param	    size	Number of bytes to read
   * @return	kSuccess on success, kFailure on failure
   */
  Result ReadFile(void* buff, size_t size);

  /**
   * @brief	    Write data from buffer to destination file
   * @param	    buff	Source buffer
   * @param	    size	Number of bytes to write
   * @return    kSuccess on success, kFailure on failure
   */
  Result WriteFile(const void* buff, size_t size);

  /**
   * @brief	    Body of the persistent asynchronous write thread
   */
  void WriterLoop();

  /**
   * @brief	    Queue a buffer for asynchronous writing
   * @param	    buff	Source buffer (must stay valid until the next SubmitWrite or FlushWrite)
   * @param	    size	Number of bytes to write
   * @return    kSuccess if the previous write succeeded, kFailure otherwise
   */
  Result SubmitWrite(const void* buff, size_t size);

  /**
   * @brief	    Wait for the in-flight write to finish
   * @return    kSuccess if every write so far succeeded, kFailure otherwise
   */
  Result FlushWrite();

  /* ==================================================
   * Decryption functions
   * ================================================== */

  /**
   * @brief   Run one decryption pass over the ciphertext
   * @param   mode   True for write, false for verify
   * @return  kSuccess on success, kFailure on failure or cancellation
   */
  Result DecryptBatch(DecryptMode mode);

  /**
   * @brief	    Intialize decryption context
   * @param	    pw		Password
   * @param	    plen	Password length
   * @return	kSuccess on success, kFailure on failure
   */
  Result DecryptInit(const char* pw, size_t plen);

  /**
   * @brief	    Decrypt buffer
   * @param	    src		Source buffer
   * @param	    dst		Destination buffer
   * @param	    srclen	Source buffer length
   * @return	kSuccess on success, kFailure on failure
   */
  Result DecryptBuff(void* src, void* dst, int srclen);

  /**
   * @brief	Finialize decryption
   * @return	kSuccess on success, kFailure on failure
   */
  Result DecryptFinal();

  /**
   * @brief   Set up decryption context and reset file cursor
   * @return  kSuccess on success, kFailure on failure
   */
  Result SetupDecryptCtx();

  /* ==================================================
   * Encryption functions
   * ================================================== */

  /**
   * @brief		Intialize encryption context
   * @param		pw		Password
   * @param		plen	Password length
   * @return	kSuccess on success, kFailure on failure
   */
  Result EncryptInit(const char* pw, size_t plen);

  /**
   * @brief		Encrypt buffer
   * @param		src		Source buffer
   * @param		dst		Destination buffer
   * @param		srclen	Source buffer length
   * @return	kSuccess on success, kFailure on failure
   */
  Result EncryptBuff(void* src, void* dst, int srclen);

  /**
   * @brief		Encrypt multiple blocks in a batch
   * @return	kSuccess on success, kFailure on failure
   */
  Result EncryptBatch();

  /**
   * @brief		Encrypt remaining data smaller than buffer
   * @return	kSuccess on success, kFailure on failure
   */
  Result EncryptRemain();

  /**
   * @brief		Finialize encryption
   * @return	kSuccess on success, kFailure on failure
   */
  Result EncryptFinal();

  /**
   * @brief		Generate and write authentication tag
   * @return	kSuccess on success, kFailure on failure
   */
  Result EncryptTag();

  /* ==================================================
   * Callback helper functions
   * ================================================== */

  /**
   * @brief		Report current progress via callback
   * @return	kContinue to continue, kCancelled if the user cancelled
   */
  Progress ReportProgress();

  /**
   * @brief		Report error via callback
   * @param		msg		Error message string
   */
  void ReportError(const char* msg);
};