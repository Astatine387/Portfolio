/**
 * @file	aes_gcm_dec.cpp
 * @brief	Implementation of decryption functions of AesGcm class
 * @author	Astatine387
 */

#include <algorithm>
#include <cstring>

#include "core/aes_gcm.h"

Result AesGcm::Decrypt(const uint8_t* src, uint8_t* dst, size_t size, const SecureKey& key,
                       std::span<const uint8_t> aad) {
  /* Everything below reads the buffer at offsets it takes on trust. The tag is lifted from src + size - kTagSize, and
   * that subtraction is size_t arithmetic, so a size under kTagSize wraps instead of going negative and the read
   * lands nowhere near the allocation. Vault::OpenVault refuses a file below kMinSize long before one reaches here,
   * but that is a check in another class on another path, and this one is public and called directly. */

  if (src == nullptr) {
    ReportError("[Crypto] Decryption failed - No source buffer to read the ciphertext from\n");
    return Result::kFailure;
  }

  if (size < kIVSize + kTagSize) {
    ReportError("[Crypto] Decryption failed - Buffer is smaller than an initial vector and authentication tag\n");
    return Result::kFailure;
  }

  /* A buffer of exactly the framing carries no plaintext, and that is the shape an empty vault decrypts through, so
   * a null destination is refused only when there would be something to write to it */

  if (dst == nullptr && size > kIVSize + kTagSize) {
    ReportError("[Crypto] Decryption failed - No destination buffer for a non-empty plaintext\n");
    return Result::kFailure;
  }

  /* Read the IV and the tag out of the buffer the caller handed over. The header, salt included, was already consumed
   * by the caller to derive the session key, so the buffer starts at the IV and ends on the tag. Neither is a secret,
   * since both go to the file in the clear, so both live in ordinary locals. */

  std::array<uint8_t, kIVSize> iv{};
  std::array<uint8_t, kTagSize> tag{};

  memcpy(iv.data(), src, kIVSize);
  memcpy(tag.data(), src + size - kTagSize, kTagSize);

  /* The context carries the expanded key. It is created here and released on the way out of this function, whichever
   * of the returns below is taken. */

  const CtxPtr ctx = MakeDecryptCtx(key, iv, tag, aad);

  if (!ctx) {
    return Result::kFailure;  // LCOV_EXCL_LINE; MakeDecryptCtx reported the error
  }

  /* Decrypt the ciphertext in chunks */

  int64_t rem = static_cast<int64_t>(size - kIVSize - kTagSize);
  size_t src_crs = kIVSize;
  size_t dst_crs = 0;

  while (rem > 0) {
    int chunk_size = static_cast<int>(std::min<int64_t>(rem, kBuffSize * kBlockSize));

    if (DecryptBuff(ctx.get(), src + src_crs, dst + dst_crs, chunk_size) == Result::kFailure) {
      return Result::kFailure;  // LCOV_EXCL_LINE
    }

    const size_t adv = static_cast<size_t>(chunk_size);

    src_crs += adv;
    dst_crs += adv;
    rem -= chunk_size;
  }

  /* The return value is computed before ctx is destroyed, so the tag is still verified against a live context */

  return DecryptFinal(ctx.get());
}

AesGcm::CtxPtr AesGcm::MakeDecryptCtx(const SecureKey& key, std::span<const uint8_t, kIVSize> iv,
                                      std::span<const uint8_t, kTagSize> tag, std::span<const uint8_t> aad) {
  CtxPtr ctx(EVP_CIPHER_CTX_new());

  if (!ctx) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Initialization failed - Cannot create context\n");
    return nullptr;
    // LCOV_EXCL_STOP
  }

  if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
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

  if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.Bytes().data(), iv.data()) != 1) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Initialization failed - Cannot set key and initial vector\n");
    return nullptr;
    // LCOV_EXCL_STOP
  }

  /* EVP_CTRL_GCM_SET_TAG takes a void* and copies the bytes into the context. They go in through a mutable copy
   * rather than a cast that throws away the constness of the caller's buffer. */

  std::array<uint8_t, kTagSize> tag_copy{};

  memcpy(tag_copy.data(), tag.data(), kTagSize);

  if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, kTagSize, tag_copy.data()) != 1) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Tag failed - Cannot set authentication tag\n");
    return nullptr;
    // LCOV_EXCL_STOP
  }

  /* Feed the associated data in the same position encryption did, ahead of any ciphertext, so the tag being verified
   * covers the same bytes in the same order */

  int out_len = 0;

  if (!aad.empty() && EVP_DecryptUpdate(ctx.get(), nullptr, &out_len, aad.data(), static_cast<int>(aad.size())) != 1) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Decryption failed - Cannot authenticate the header\n");
    return nullptr;
    // LCOV_EXCL_STOP
  }

  return ctx;
}

Result AesGcm::DecryptBuff(EVP_CIPHER_CTX* ctx, const uint8_t* src, uint8_t* dst, int len) {
  int out_len;

  if (EVP_DecryptUpdate(ctx, dst, &out_len, src, len) != 1) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Decryption failed - Cannot decrypt buffer\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  if (out_len != len) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Decryption failed - Cannot decrypt buffer\n");
    return Result::kFailure;
    // LCOV_EXCL_STOP
  }

  return Result::kSuccess;
}

Result AesGcm::DecryptFinal(EVP_CIPHER_CTX* ctx) {
  std::array<uint8_t, kBlockSize> final_block{};
  int final_len;

  if (EVP_DecryptFinal_ex(ctx, final_block.data(), &final_len) != 1) {
    ReportError("[Auth] Verification failed - Invalid password or corrupted vault\n");
    return Result::kFailure;
  }

  return Result::kSuccess;
}
