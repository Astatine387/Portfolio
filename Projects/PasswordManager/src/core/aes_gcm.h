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
#include <memory>
#include <span>

#include "common/constants.h"
#include "core/secure_key.h"

/**
 * @class	AesGcm
 * @brief	AES-256-GCM engine
 *
 * Everything one operation needs — the cipher context, the initial vector, the tag, the key and the buffers — belongs
 * to that operation and dies with it. Only the error callback outlives a call, because it is what the owner installs
 * once and expects to stay installed.
 */
class AesGcm {
 public:
  /* ==================================================
   * Constructor, destructor, operators
   * ================================================== */

  /**
   * @brief   Default constructor of AesGcm class
   */
  AesGcm() = default;

  /**
   * @brief   Destructor of AesGcm class
   */
  ~AesGcm() = default;

  AesGcm(const AesGcm&) = delete;             // Delete copy constructor
  AesGcm& operator=(const AesGcm&) = delete;  // Delete copy assignment operator
  AesGcm(AesGcm&&) = delete;                  // Delete move constructor
  AesGcm& operator=(AesGcm&&) = delete;       // Delete move assignment operator

  /* ==================================================
   * Interface functions
   * ================================================== */

  /**
   * @brief		Decrypt a buffer
   * @param		src		Source buffer, laid out as [iv][ciphertext][tag]
   * @param		dst		Destination buffer
   * @param		size	Source buffer size
   * @param		key		Session key
   * @param		aad		Associated data, authenticated but neither read from nor written to @p src
   * @return  kSuccess on success, kFailure on failure
   *
   * The call is refused with kFailure, before either buffer is touched, when @p src is null, when @p size is under
   * kIVSize + kTagSize, or when @p dst is null while @p size leaves a plaintext to write. The size is not a
   * formality: the tag is read from @p src + @p size - kTagSize, and that subtraction wraps rather than going
   * negative. A @p size of exactly kIVSize + kTagSize describes an empty plaintext and is accepted, @p dst null
   * along with it.
   *
   * AES-GCM cannot authenticate the ciphertext until the whole message has been processed. On kFailure @p dst holds
   * unverified plaintext. The caller owns that buffer and must wipe it before doing anything else with it.
   *
   * @p aad has to be byte-for-byte what encryption was given or the tag fails. The caller is expected to hand over a
   * view into the very buffer the header was read into, rather than a header it rebuilt from parsed fields, so that
   * the bytes on the disk and the bytes under the tag cannot drift apart.
   *
   * @p key is borrowed for the duration of the call and nothing derived from it survives the return.
   */
  Result Decrypt(uint8_t* src, uint8_t* dst, size_t size, const SecureKey& key, std::span<const uint8_t> aad);

  /**
   * @brief		Encrypt a buffer
   * @param		src   Source buffer
   * @param		dst   Destination buffer, laid out as [iv][ciphertext][tag]
   * @param		size  Source buffer size
   * @param		key   Session key
   * @param		aad   Associated data, authenticated but not copied into @p dst
   * @return  kSuccess on success, kFailure on failure
   *
   * The call is refused with kFailure, before either buffer is touched, when @p dst is null, which is refused at
   * every @p size because the IV and the tag are written even for an empty plaintext, or when @p src is null while
   * @p size is not zero. A @p size of zero is accepted, @p src null along with it.
   *
   * The header is not this class's business: it neither writes the salt nor knows what the bytes it authenticates
   * mean, and @p dst begins at the IV. Whoever owns the header writes it and passes the same bytes here.
   *
   * @p key is borrowed for the duration of the call and nothing derived from it survives the return.
   */
  Result Encrypt(uint8_t* src, uint8_t* dst, size_t size, const SecureKey& key, std::span<const uint8_t> aad);

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
   * @struct  CtxGuard
   * @brief   Releases a cipher context, and with it the expanded key OpenSSL keeps inside one
   *
   * EVP_CIPHER_CTX_free cleanses the cipher data before releasing it, so this is both the release and the wipe. An
   * empty type rather than a function pointer, so that a CtxPtr is the size of the pointer it wraps.
   */
  struct CtxGuard {
    void operator()(EVP_CIPHER_CTX* ctx) const noexcept { EVP_CIPHER_CTX_free(ctx); }
  };

  /**
   * @brief	Owning handle for the cipher context of one operation
   *
   * Declared where the operation is, never as a member, so that the expanded key cannot outlive the call whichever
   * way that call returns.
   */
  using CtxPtr = std::unique_ptr<EVP_CIPHER_CTX, CtxGuard>;

  ErrorCallback ecb_ = nullptr;  // Error reporting callback function

  /* ==================================================
   * Decryption functions
   * ================================================== */

  /**
   * @brief   Create the decryption context and set key, IV, tag and associated data
   * @param   key   Session key
   * @param   iv    Initial vector read from the source buffer
   * @param   tag   Authentication tag read from the source buffer
   * @param   aad   Associated data to authenticate
   * @return  The context on success, nullptr on failure
   */
  [[nodiscard]] CtxPtr MakeDecryptCtx(const SecureKey& key, std::span<const uint8_t, kIVSize> iv,
                                      std::span<const uint8_t, kTagSize> tag, std::span<const uint8_t> aad);

  /**
   * @brief   Decrypt a buffer
   * @param   ctx   Cipher context of the operation in progress
   * @param   src   Source buffer
   * @param   dst   Destination buffer
   * @param   len   Source buffer length
   * @return  kSuccess on success, kFailure on failure
   */
  Result DecryptBuff(EVP_CIPHER_CTX* ctx, const uint8_t* src, uint8_t* dst, int len);

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
   * @brief   Create the encryption context, set key and IV, and authenticate the associated data
   * @param   key   Session key
   * @param   iv    Initial vector generated for this operation
   * @param   aad   Associated data to authenticate
   * @return  The context on success, nullptr on failure
   */
  [[nodiscard]] CtxPtr MakeEncryptCtx(const SecureKey& key, std::span<const uint8_t, kIVSize> iv,
                                      std::span<const uint8_t> aad);

  /**
   * @brief   Encrypt buffer
   * @param   ctx   Cipher context of the operation in progress
   * @param   src   Source buffer, null only when @p size is zero
   * @param   dst   Destination buffer, positioned after the initial vector
   * @param   size  Source buffer size
   * @return  kSuccess on success, kFailure on failure
   */
  Result EncryptBuff(EVP_CIPHER_CTX* ctx, const uint8_t* src, uint8_t* dst, size_t size);

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
   * @param   msg Error message string
   */
  void ReportError(const char* msg);
};
