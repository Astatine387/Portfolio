/**
 * @file    aes_gcm.h
 * @brief   AES-256-GCM file encryption engine
 * @author  Astatine387
 */

#pragma once

#include <openssl/evp.h>

#include <array>
#include <atomic>
#include <cstdint>
#include <functional>
#include <thread>
#include <vector>

#include "common/constants.h"
#include "core/file_header.h"
#include "core/secure_key.h"
#include "utils/mutex.h"
#include "utils/thread_annotations.h"

/**
 * @brief   AES-256-GCM file encryption/decryption engine
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

  AesGcm(const AesGcm&) = delete;
  AesGcm& operator=(const AesGcm&) = delete;
  AesGcm(AesGcm&&) = delete;
  AesGcm& operator=(AesGcm&&) = delete;

  /* ==================================================
   * Interface functions
   * ================================================== */

  /**
   * @brief		Decrypt a file
   * @param		src     Source file
   * @param		dst     Destination file
   * @param		key     Key derived from the password and the salt
   * @param		header  File header
   * @return  kSuccess on success, kFailure on failure
   */
  Result Decrypt(FILE* src, FILE* dst, const SecureKey& key,
                 const FileHeader& header);

  /**
   * @brief		Encrypt a file
   * @param		src     Source file
   * @param		dst     Destination file
   * @param		key     Key derived from the password and salt
   * @return  kSuccess on success, kFailure on failure
   */
  Result Encrypt(FILE* src, FILE* dst, const SecureKey& key);

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
   * Guarded, because two errors may arrive at once from two threads
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
   */
  void SetCancelFlag(const std::atomic<bool>* flag) { cancel_ = flag; }

 private:
  EVP_CIPHER_CTX* ctx_ = nullptr;  // OpenSSL encryption/decryption context

  FILE* src_file_ = nullptr;  // Source file
  FILE* dst_file_ = nullptr;  // Destination file

  // Error reporting callback
  ErrorCallback ecb_ GUARDED_BY(error_mtx_) = nullptr;

  // Progress reporting callback
  ProgressCallback pcb_ = nullptr;

  // Mutex for error reporting callbacks
  Mutex error_mtx_;

  const std::atomic<bool>* cancel_ = nullptr;  // Cancellation flag

  int64_t src_size_ = 0;      // Source file size
  int64_t progress_cur_ = 0;  // Current processed bytes
  int64_t progress_max_ = 0;  // Total bytes to be processed
  int last_perc_ = -1;  // Last reported percent, -1 before the first report

  // Chunk size of the current session
  size_t chunk_size_ = kChunkSize;

  // Chunk buffers
  std::array<std::vector<uint8_t>, kBuffNum> buff_{};

  // File header of the current session
  std::array<uint8_t, kHeaderSize> header_{};

  // Nonce of the current chunk
  std::array<uint8_t, kNonceSize> nonce_{};

  const SecureKey* key_ = nullptr;  // Session key for the current operation

  /* ==================================================
   * Hand-off slots between the threads
   * ================================================== */

  std::thread writer_;          // Asynchronous write thread
  Mutex write_mtx_;             // Mutex for write hand-off
  ConditionVariable write_cv_;  // Signals job-ready and job-done transitions

  // Buffer queued for writing
  const void* write_buff_ GUARDED_BY(write_mtx_) = nullptr;

  // Number of bytes queued for writing
  size_t write_size_ GUARDED_BY(write_mtx_) = 0;

  // Whether a write job is queued or in progress
  bool write_pending_ GUARDED_BY(write_mtx_) = false;

  // Whether the writer thread should exit
  bool writer_stop_ GUARDED_BY(write_mtx_) = false;

  // Result of the most recent write
  Result write_result_ GUARDED_BY(write_mtx_) = Result::kSuccess;

  /* ==================================================
   * I/O helper functions
   * ================================================== */

  /**
   * @brief   Read data from source file into buffer
   * @param   buff  Destination buffer
   * @param   size  Number of bytes to read
   * @return  kSuccess on success, kFailure on failure
   */
  Result ReadFile(void* buff, size_t size);

  /**
   * @brief   Write data from buffer to destination file
   * @param   buff  Source buffer
   * @param   size  Number of bytes to write
   * @return  kSuccess on success, kFailure on failure
   */
  Result WriteFile(const void* buff, size_t size);

  /**
   * @brief   Body of the asynchronous write thread
   */
  void WriterLoop() noexcept;

  /**
   * @brief   Queue a buffer for asynchronous writing
   * @param   buff  Source buffer
   * @param   size  Number of bytes to write
   * @return  kSuccess if the previous write succeeded, kFailure otherwise
   */
  Result SubmitWrite(const void* buff, size_t size);

  /**
   * @brief   Wait for the ongoing write to finish
   * @return  kSuccess if every write so far succeeded, kFailure otherwise
   */
  Result FlushWrite();

  /**
   * @brief   Drain any ongoing asynchronous write when the scope exits
   */
  class WriterGuard {
   public:
    explicit WriterGuard(AesGcm* self) : self_(self) {}
    ~WriterGuard() { self_->FlushWrite(); }

    WriterGuard(const WriterGuard&) = delete;
    WriterGuard& operator=(const WriterGuard&) = delete;
    WriterGuard(WriterGuard&&) = delete;
    WriterGuard& operator=(WriterGuard&&) = delete;

   private:
    AesGcm* self_;  // Owner engine whose write is drained on scope exit
  };

  /* ==================================================
   * Chunk helper functions
   * ================================================== */

  /**
   * @brief   Build the nonce of one chunk
   * @param   idx       Chunk index
   * @param   is_last   Last-chunk flag
   */
  void BuildNonce(uint64_t idx, bool is_last);

  /**
   * @brief   Size chunk buffers for the current session
   */
  void AllocBuffers();

  /**
   * @brief   Create a fresh context and set the session key
   * @param   mode  Either encryption or decryption
   * @return  kSuccess on success, kFailure on failure
   *
   * The key schedule is computed only once here.
   */
  Result SetupCtx(CryptoMode mode);

  /* ==================================================
   * Decryption functions
   * ================================================== */

  /**
   * @brief   Check the header, prepare the context and buffers
   * @param   header  Header read from the source file
   * @return  kSuccess on success, kFailure on failure
   */
  Result DecryptInit(const FileHeader& header);

  /**
   * @brief   Verify and write every chunk of the file
   * @return	kSuccess on success, kFailure on failure or cancellation
   */
  Result DecryptLoop();

  /**
   * @brief   Verify one chunk and decrypt it in place
   * @param   buff      Buffer holding the ciphertext followed by its tag
   * @param   len       Ciphertext length in bytes, tag excluded
   * @param   idx       Chunk index
   * @param   is_last   Whether this is the final chunk of the file
   * @return	kSuccess when the tag verifies, kFailure otherwise
   */
  Result DecryptChunk(uint8_t* buff, size_t len, uint64_t idx, bool is_last);

  /* ==================================================
   * Encryption functions
   * ================================================== */

  /**
   * @brief   Write the header, prepare the context and buffers
   * @return  kSuccess on success, kFailure on failure
   */
  Result EncryptInit();

  /**
   * @brief   Encrypt and write the file
   * @return  kSuccess on success, kFailure on failure or cancellation
   */
  Result EncryptLoop();

  /**
   * @brief   Encrypt one chunk in place and append its tag
   * @param   buff      Buffer holding the plaintext, with room for the tag
   * @param		len       Plaintext length in bytes
   * @param		idx       Chunk index
   * @param		is_last   Whether this is the final chunk of the file
   * @return  kSuccess on success, kFailure on failure
   */
  Result EncryptChunk(uint8_t* buff, size_t len, uint64_t idx, bool is_last);

  /* ==================================================
   * Callback helper functions
   * ================================================== */

  /**
   * @brief   Report current progress via callback
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
