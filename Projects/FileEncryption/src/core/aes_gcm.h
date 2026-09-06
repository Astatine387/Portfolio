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
#include <atomic>
#include <cstdint>
#include <functional>
#include <span>
#include <thread>
#include <vector>

#include "common/constants.h"
#include "core/file_header.h"
#include "core/secure_key.h"
#include "utils/mutex.h"
#include "utils/thread_annotations.h"

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
   * @param		key		Key derived from the password and the salt
   * @return    kSuccess on success, kFailure on failure
   */
  Result Decrypt(FILE* src, FILE* dst, const SecureKey& key);

  /**
   * @brief		Encrypt a file
   * @param		src     Source file
   * @param		dst     Destination file
   * @param		key     Key derived from the password and salt
   * @param		salt    Salt written to the file header
   * @param		params  Argon2id parameters
   * @return  kSuccess on success, kFailure on failure
   */
  Result Encrypt(FILE* src, FILE* dst, const SecureKey& key, std::span<const uint8_t, kSaltSize> salt,
                 const KdfParams& params = {});

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
   */
  using ProgressCallback = std::function<void(int perc)>;

  /**
   * @brief		Set error callback function
   * @param		ecb		Error callback function
   *
   * Guarded, unlike the progress callback below: an error can come from the writer thread as well as
   * from the thread doing the reading and the crypto, so two of them can arrive at once.
   */
  void SetErrorCallback(ErrorCallback ecb) {
    UniqueLock lk(error_mtx_);
    ecb_ = std::move(ecb);
  }

  /**
   * @brief		Set progress callback function
   * @param		pcb		Progress callback function
   */
  void SetProgressCallback(ProgressCallback pcb) { pcb_ = std::move(pcb); }

  /**
   * @brief		Set the cancellation flag
   * @param		flag	Cancellation flag
   *
   * Borrowed, not owned. The flag belongs to whoever may raise it and has to outlive the engine, which
   * holds for the worker that owns both.
   */
  void SetCancelFlag(const std::atomic<bool>* flag) { cancel_ = flag; }

 private:
  EVP_CIPHER_CTX* ctx_ = nullptr;  // OpenSSL encryption/decryption context

  FILE* src_file_ = nullptr;  // Source file
  FILE* dst_file_ = nullptr;  // Destination file

  ErrorCallback ecb_ GUARDED_BY(error_mtx_) = nullptr;  // Error reporting callback function
  ProgressCallback pcb_ = nullptr;                      // Progress reporting callback function
  Mutex error_mtx_;  // Serializes error callback calls from the read and write threads

  const std::atomic<bool>* cancel_ = nullptr;  // Cancellation flag

  int64_t src_size_ = 0;      // Source file size
  int64_t progress_cur_ = 0;  // Current progress
  int64_t progress_max_ = 0;  // Total work for progress reporting
  int last_perc_ = -1;        // Last reported whole percent, -1 before the first report

  size_t chunk_size_ = kChunkSize;                     // Chunk size of the current session
  std::array<std::vector<uint8_t>, kBuffNum> buff_{};  // Chunk buffers
  std::array<uint8_t, kHeaderSize> header_{};          // Serialized header, associated data of every chunk
  std::array<uint8_t, kNonceSize> nonce_{};            // Nonce of the chunk being processed
  std::array<uint8_t, kSaltSize> salt_{};              // Salt read from the header

  const SecureKey* key_ = nullptr;  // Session key for the current operation (non-owning)

  /* The five fields below are one hand-off slot, not a queue: the producer fills it, the writer empties
   * it, and SubmitWrite blocks until it is free again. That bound is what lets two chunk buffers be
   * enough, since only one of them can be in the writer's hands at a time. */

  std::thread writer_;          // Long-lived asynchronous write worker
  Mutex write_mtx_;             // Serializes the write hand-off state
  ConditionVariable write_cv_;  // Signals job-ready and job-done transitions

  const void* write_buff_ GUARDED_BY(write_mtx_) = nullptr;        // Buffer queued for writing
  size_t write_size_ GUARDED_BY(write_mtx_) = 0;                   // Number of bytes queued for writing
  bool write_pending_ GUARDED_BY(write_mtx_) = false;              // Whether a write job is queued or in progress
  bool writer_stop_ GUARDED_BY(write_mtx_) = false;                // Whether the writer thread should exit
  Result write_result_ GUARDED_BY(write_mtx_) = Result::kSuccess;  // Result of the most recent write

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
  void WriterLoop() noexcept;

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

  /**
   * @class   WriterGuard
   * @brief   Drain any in-flight asynchronous write when the scope exits
   *
   * Every exit from Encrypt and Decrypt goes through it, early returns included. That is what lets the
   * caller close the destination file the moment the call returns: the writer thread is done with it.
   */
  class WriterGuard {
   public:
    explicit WriterGuard(AesGcm* self) : self_(self) {}
    ~WriterGuard() { self_->FlushWrite(); }

    WriterGuard(const WriterGuard&) = delete;             // Delete copy constructor
    WriterGuard& operator=(const WriterGuard&) = delete;  // Delete copy assignment operator
    WriterGuard(WriterGuard&&) = delete;                  // Delete move constructor
    WriterGuard& operator=(WriterGuard&&) = delete;       // Delete move assignment operator

   private:
    AesGcm* self_;  // Owner engine whose write is drained on scope exit
  };

  /* ==================================================
   * Chunk helper functions
   * ================================================== */

  /**
   * @brief	    Build the nonce of one chunk
   * @param	    idx       Chunk index
   * @param	    is_last   Whether this is the final chunk
   */
  void BuildNonce(uint64_t idx, bool is_last);

  /**
   * @brief	    Size chunk buffers for the current session
   */
  void AllocBuffers();

  /**
   * @brief	    Set the session key on a freshly created context
   * @param	    mode	kEncrypt for an encryption context, kDecrypt for a decryption context
   * @return    kSuccess on success, kFailure on failure
   *
   * The key schedule is computed once here; each chunk only re-initializes the nonce.
   */
  Result SetupCtx(CryptoMode mode);

  /* ==================================================
   * Decryption functions
   * ================================================== */

  /**
   * @brief   Read and validate the header, then prepare the context and buffers
   * @return  kSuccess on success, kFailure on failure
   */
  Result DecryptInit();

  /**
   * @brief   Verify and write every chunk of the file in a single pass
   * @return	kSuccess on success, kFailure on failure or cancellation
   */
  Result DecryptLoop();

  /**
   * @brief	    Verify one chunk and decrypt it in place
   * @param	    buff      Buffer holding the ciphertext followed by its tag
   * @param	    len       Ciphertext length in bytes, tag excluded
   * @param	    idx       Chunk index
   * @param	    is_last   Whether this is the final chunk of the file
   * @return	kSuccess when the tag verifies, kFailure otherwise
   */
  Result DecryptChunk(uint8_t* buff, size_t len, uint64_t idx, bool is_last);

  /* ==================================================
   * Encryption functions
   * ================================================== */

  /**
   * @brief		Write the header, then prepare the context and buffers
   * @param		salt    Salt written to the file header
   * @param		params  Argon2id parameters written to the file header
   * @return	kSuccess on success, kFailure on failure
   */
  Result EncryptInit(std::span<const uint8_t, kSaltSize> salt, const KdfParams& params);

  /**
   * @brief		Encrypt and write every chunk of the file in a single pass
   * @return	kSuccess on success, kFailure on failure or cancellation
   */
  Result EncryptLoop();

  /**
   * @brief		Encrypt one chunk in place and append its tag
   * @param		buff      Buffer holding the plaintext, with room for the tag after it
   * @param		len       Plaintext length in bytes
   * @param		idx       Chunk index
   * @param		is_last   Whether this is the final chunk of the file
   * @return	kSuccess on success, kFailure on failure
   */
  Result EncryptChunk(uint8_t* buff, size_t len, uint64_t idx, bool is_last);

  /* ==================================================
   * Callback helper functions
   * ================================================== */

  /**
   * @brief		Report current progress via callback
   */
  void ReportProgress();

  /**
   * @brief		Poll the cancellation flag
   * @return	true if the user requested cancellation
   */
  [[nodiscard]] bool IsCancelled() const;

  /**
   * @brief		Report error via callback
   * @param		msg		Error message string
   */
  void ReportError(const char* msg);
};
