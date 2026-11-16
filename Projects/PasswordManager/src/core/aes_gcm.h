/**
 * @file    aes_gcm.h
 * @brief   AES-GCM encryption/decryption engine
 * @author  Astatine387
 */

#pragma once

#include <openssl/evp.h>

#include <array>
#include <functional>
#include <future>
#include <memory>
#include <span>

#include "common/constants.h"
#include "core/secure_key.h"

/**
 * @brief   AES-256-GCM buffer encryption/decryption engine
 */
class AesGcm {
 public:
  /* ==================================================
   * Constructor, destructor, operators
   * ================================================== */

  /**
   * @brief   Default constructor of AesGcm
   */
  AesGcm() = default;

  /**
   * @brief   Destructor of AesGcm
   */
  ~AesGcm() = default;

  AesGcm(const AesGcm&) = delete;
  AesGcm& operator=(const AesGcm&) = delete;
  AesGcm(AesGcm&&) = delete;
  AesGcm& operator=(AesGcm&&) = delete;

  /* ==================================================
   * Interface functions
   * ================================================== */

  /**
   * @brief   Decrypt a buffer
   * @param   src   Source buffer, laid out as [iv][ciphertext][tag]
   * @param   dst   Destination buffer
   * @param   size  Source buffer size
   * @param   key   Session key
   * @param   aad   Associated data, byte-for-byte what encryption was given
   * @return  kSuccess on success, kFailure on failure
   *
   * Fails without touching either buffer when @p src is null, @p size is under
   * kIVSize + kTagSize, or @p dst is null while there is a plaintext to write.
   * On kFailure @p dst may hold unverified plaintext, which the caller must
   * wipe. Nothing derived from @p key outlives the call.
   */
  Result Decrypt(const uint8_t* src, uint8_t* dst, size_t size,
                 const SecureKey& key, std::span<const uint8_t> aad);

  /**
   * @brief   Encrypt a buffer
   * @param   src   Source buffer
   * @param   dst   Destination buffer, laid out as [iv][ciphertext][tag]
   * @param   size  Source buffer size
   * @param   key   Session key
   * @param   aad   Associated data, authenticated but not copied into @p dst
   * @return  kSuccess on success, kFailure on failure
   *
   * Fails without touching either buffer when @p dst is null, or when @p src is
   * null while @p size is not zero. Nothing derived from @p key outlives the
   * call.
   */
  Result Encrypt(const uint8_t* src, uint8_t* dst, size_t size,
                 const SecureKey& key, std::span<const uint8_t> aad);

  /* ==================================================
   * Callback functions
   * ================================================== */

  /**
   * @brief   Callback function for error reporting
   * @param   msg   Error message string
   */
  using ErrorCallback = std::function<void(const char* msg)>;

  /**
   * @brief   Set error callback function
   * @param   ecb   Error callback function
   */
  void SetErrorCallback(ErrorCallback ecb) { ecb_ = std::move(ecb); }

 private:
  /**
   * @brief   Releases a cipher context, and with it the expanded key OpenSSL
   * keeps inside one
   */
  struct CtxGuard {
    void operator()(EVP_CIPHER_CTX* ctx) const noexcept {
      EVP_CIPHER_CTX_free(ctx);
    }
  };

  /**
   * @brief   Owning handle for the cipher context of one operation
   */
  using CtxPtr = std::unique_ptr<EVP_CIPHER_CTX, CtxGuard>;

  ErrorCallback ecb_ = nullptr;  // Error reporting callback function

  /* ==================================================
   * Decryption functions
   * ================================================== */

  /**
   * @brief   Create the decryption context and set key, IV, tag and associated
   * data
   * @param   key   Session key
   * @param   iv    Initial vector read from the source buffer
   * @param   tag   Authentication tag read from the source buffer
   * @param   aad   Associated data to authenticate
   * @return  The context on success, nullptr on failure
   */
  [[nodiscard]] CtxPtr MakeDecryptCtx(const SecureKey& key,
                                      std::span<const uint8_t, kIVSize> iv,
                                      std::span<const uint8_t, kTagSize> tag,
                                      std::span<const uint8_t> aad);

  /**
   * @brief   Decrypt a buffer
   * @param   ctx   Cipher context of the operation in progress
   * @param   src   Source buffer
   * @param   dst   Destination buffer
   * @param   len   Source buffer length
   * @return  kSuccess on success, kFailure on failure
   */
  Result DecryptBuff(EVP_CIPHER_CTX* ctx, const uint8_t* src, uint8_t* dst,
                     int len);

  /**
   * @brief   Finalize decryption and verify the authentication tag
   * @param   ctx   Cipher context of the operation in progress
   * @return  kSuccess on success, kFailure on failure
   */
  Result DecryptFinal(EVP_CIPHER_CTX* ctx);

  /* ==================================================
   * Encryption functions
   * ================================================== */

  /**
   * @brief   Create the encryption context, set key and IV, and authenticate
   * the associated data
   * @param   key   Session key
   * @param   iv    Initial vector generated for this operation
   * @param   aad   Associated data to authenticate
   * @return  The context on success, nullptr on failure
   */
  [[nodiscard]] CtxPtr MakeEncryptCtx(const SecureKey& key,
                                      std::span<const uint8_t, kIVSize> iv,
                                      std::span<const uint8_t> aad);

  /**
   * @brief   Encrypt buffer
   * @param   ctx   Cipher context of the operation in progress
   * @param   src   Source buffer, null only when @p size is zero
   * @param   dst   Destination buffer, positioned after the initial vector
   * @param   size  Source buffer size
   * @return  kSuccess on success, kFailure on failure
   */
  Result EncryptBuff(EVP_CIPHER_CTX* ctx, const uint8_t* src, uint8_t* dst,
                     size_t size);

  /**
   * @brief   Finalize encryption
   * @param   ctx   Cipher context of the operation in progress
   * @return  kSuccess on success, kFailure on failure
   */
  Result EncryptFinal(EVP_CIPHER_CTX* ctx);

  /**
   * @brief   Generate and write authentication tag
   * @param   ctx   Cipher context of the operation in progress
   * @param   dst   Destination of the tag, at the end of the ciphertext
   * @return  kSuccess on success, kFailure on failure
   */
  Result EncryptTag(EVP_CIPHER_CTX* ctx, std::span<uint8_t, kTagSize> dst);

  /* ==================================================
   * Callback helper functions
   * ================================================== */

  /**
   * @brief   Report error via callback
   * @param   msg   Error message string
   */
  void ReportError(const char* msg);
};
