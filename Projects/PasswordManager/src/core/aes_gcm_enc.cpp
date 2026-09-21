/**
 * @file	aes_gcm_enc.cpp
 * @brief	Implementation of encryption functions of AesGcm class
 * @author	Astatine387
 */

#include <cstring>
#include <utility>

#include "core/aes_gcm.h"
#include "utils/platform.h"

Result AesGcm::Encrypt(const uint8_t* src, uint8_t* dst, size_t size, const SecureKey& key,
                       std::span<const uint8_t> aad) {
  /* The destination is written at every size, an empty plaintext included, since the IV and the tag go into it
   * regardless. The source is read only when there is a plaintext to read, so a caller holding the .data() of an
   * empty container may hand that over null rather than having to invent a pointer for zero bytes. */

  if (dst == nullptr) {
    ReportError("[Crypto] Encryption failed - No destination buffer to write the ciphertext to\n");
    return Result::kFailure;
  }

  if (size > 0 && src == nullptr) {
    ReportError("[Crypto] Encryption failed - No source buffer for a non-empty plaintext\n");
    return Result::kFailure;
  }

  /* Generate a new IV for every encryption. It goes to the file in the clear and carries no secret, so an ordinary
   * local is where it belongs and there is nothing here to wipe. */

  std::array<uint8_t, kIVSize> iv{};

  if (Random(iv.data(), kIVSize) == Result::kFailure) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Random failed - Cannot generate initial vector\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  /* The context carries the expanded key. It is created here and released on the way out of this function, whichever
   * of the returns below is taken. */

  const CtxPtr ctx = MakeEncryptCtx(key, iv, aad);

  if (!ctx) {
    return Result::kFailure;  // LCOV_EXCL_LINE; MakeEncryptCtx reported the error
  }

  /* Write the fresh IV. The header ahead of it belongs to the caller, which has already written it and passed those
   * same bytes in as the associated data. */

  memcpy(dst, iv.data(), kIVSize);

  if (EncryptBuff(ctx.get(), src, dst + kIVSize, size) == Result::kFailure) {
    return Result::kFailure;  // LCOV_EXCL_LINE
  }

  if (EncryptFinal(ctx.get()) == Result::kFailure) {
    return Result::kFailure;  // LCOV_EXCL_LINE
  }

  if (EncryptTag(ctx.get(), std::span<uint8_t, kTagSize>(dst + kIVSize + size, kTagSize)) == Result::kFailure) {
    return Result::kFailure;  // LCOV_EXCL_LINE
  }

  return Result::kSuccess;
}

AesGcm::CtxPtr AesGcm::MakeEncryptCtx(const SecureKey& key, std::span<const uint8_t, kIVSize> iv,
                                      std::span<const uint8_t> aad) {
  CtxPtr ctx(EVP_CIPHER_CTX_new());

  if (!ctx) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Initialization failed - Cannot create context\n");
    return nullptr;
    // LCOV_EXCL_STOP
  }

  if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Initialization failed - Cannot set AES-256-GCM algorithm\n");
    return nullptr;
    // LCOV_EXCL_STOP
  }

  if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, kIVSize, nullptr) != 1) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Initialization failed - Cannot set initial vector size\n");
    return nullptr;
    // LCOV_EXCL_STOP
  }

  if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.Bytes().data(), iv.data()) != 1) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Initialization failed - Cannot set key and initial vector\n");
    return nullptr;
    // LCOV_EXCL_STOP
  }

  /* Authenticate the associated data before any plaintext reaches the context. A null output buffer is what makes
   * EVP_EncryptUpdate feed bytes in as associated data rather than encrypt them, and GCM requires all of it ahead of
   * the first ciphertext byte: fed later it would silently produce a different tag instead of an error. */

  int out_len = 0;

  if (!aad.empty() && EVP_EncryptUpdate(ctx.get(), nullptr, &out_len, aad.data(), static_cast<int>(aad.size())) != 1) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Encryption failed - Cannot authenticate the header\n");
    return nullptr;
    // LCOV_EXCL_STOP
  }

  return ctx;
}

Result AesGcm::EncryptBuff(EVP_CIPHER_CTX* ctx, const uint8_t* src, uint8_t* dst, size_t size) {
  int out_len;

  /* constants.h asserts that kMaxSize leaves no image longer than the int length this call takes */

  if (EVP_EncryptUpdate(ctx, dst, &out_len, src, static_cast<int>(size)) != 1) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Encryption failed - Cannot encrypt buffer\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  if (std::cmp_not_equal(out_len, size)) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Encryption failed - Cannot encrypt buffer\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  return Result::kSuccess;
}

Result AesGcm::EncryptFinal(EVP_CIPHER_CTX* ctx) {
  std::array<uint8_t, kBlockSize> final_block{};
  int final_len;

  if (EVP_EncryptFinal_ex(ctx, final_block.data(), &final_len) != 1) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Finalization failed - Cannot finalize encryption\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  if (final_len > 0) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Finalization failed - Unexpected output from finalization\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  return Result::kSuccess;
}

Result AesGcm::EncryptTag(EVP_CIPHER_CTX* ctx, std::span<uint8_t, kTagSize> dst) {
  std::array<uint8_t, kTagSize> tag{};

  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, kTagSize, tag.data()) != 1) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Tag Error - Cannot get authentication tag\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  memcpy(dst.data(), tag.data(), kTagSize);

  return Result::kSuccess;
}
