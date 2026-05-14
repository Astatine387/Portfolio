/**
 * @file	AES_GCM_enc.cpp
 * @brief	Implementation of encryption function of AES_GCM class
 * @author	Astatine387
 */

#include "Core/AES_GCM.h"
#include "Utils/library.h"

int AesGcm::Encrypt(FILE* src, FILE* dst, const char* pw, size_t plen) {
  src_file_ = src;
  dst_file_ = dst;
  cancelled_ = false;
  progress_ = 0;
  writing_ = false;

  if (EncryptInit(pw, plen)) {
    return 1;  // LCOV_EXCL_LINE
  }

  if (EncryptBatch()) {
    return 1;  // LCOV_EXCL_LINE
  }

  if (EncryptRemain()) {
    return 1;  // LCOV_EXCL_LINE
  }

  if (EncryptFinal()) {
    return 1;  // LCOV_EXCL_LINE
  }

  if (EncryptTag()) {
    return 1;  // LCOV_EXCL_LINE
  }

  return 0;
}

int AesGcm::EncryptInit(const char* pw, size_t plen) {
  /* Clear existing context */

  if (ctx_) {
    EVP_CIPHER_CTX_free(ctx_);
    ctx_ = nullptr;
  }

  /* Get source file size */

  src_size_ = GetFileSize(src_file_);

  if (src_size_ == -1) {
    // LCOV_EXCL_START
    ReportError("[File] Size check failed - Cannot read source file size\n");
    return 1;
    // LCOV_EXCL_STOP
  }

  if (src_size_ > kMaxSize) {
    // LCOV_EXCL_START
    ReportError("[File] Validation failed - File should be at most 64 GiB\n");
    return 1;
    // LCOV_EXCL_STOP
  }

  /* Generate salt and IV */

  if (Random(salt_, kSaltSize)) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Random failed - Cannot generate salt\n");
    return 1;
    // LCOV_EXCL_STOP
  }

  if (Random(iv_, kIVSize)) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Random failed - Cannot generate initial vector\n");
    return 1;
    // LCOV_EXCL_STOP
  }

  /* Derive key from password */

  if (Argon2id(salt_, pw, plen, key_)) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Key derivation failed - Argon2id error\n");
    return 1;
    // LCOV_EXCL_STOP
  }

  /* Set encryption context */

  if (!(ctx_ = EVP_CIPHER_CTX_new())) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Initialization failed - Cannot create context\n");
    return 1;
    // LCOV_EXCL_STOP
  }

  if (EVP_EncryptInit_ex(ctx_, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Initialization failed - Cannot set AES-256-GCM algorithm\n");
    return 1;
    // LCOV_EXCL_STOP
  }

  if (EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_GCM_SET_IVLEN, kIVSize, NULL) != 1) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Initialization failed - Cannot set initial vector size\n");
    return 1;
    // LCOV_EXCL_STOP
  }

  if (EVP_EncryptInit_ex(ctx_, NULL, NULL, key_, iv_) != 1) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Initialization failed - Cannot set key and initial vector\n");
    return 1;
    // LCOV_EXCL_STOP
  }

  /* Write salt and IV */

  if (fwrite(salt_, sizeof(uint8_t), kSaltSize, dst_file_) != kSaltSize) {
    // LCOV_EXCL_START
    ReportError("[File] Write failed - Cannot write salt to destination file header\n");
    return 1;
    // LCOV_EXCL_STOP
  }

  if (fwrite(iv_, sizeof(uint8_t), kIVSize, dst_file_) != kIVSize) {
    // LCOV_EXCL_START
    ReportError("[File] Write failed - Cannot write initial vector to destination file header\n");
    return 1;
    // LCOV_EXCL_STOP
  }

  return 0;
}

int AesGcm::EncryptBuff(void* src, void* dst, int srclen) {
  int dstlen;

  if (EVP_EncryptUpdate(ctx_, static_cast<unsigned char*>(dst), &dstlen,
                        static_cast<unsigned char*>(src), srclen) != 1) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Encryption failed - Cannot encrypt buffer\n");
    return 1;
    // LCOV_EXCL_STOP
  }

  if (dstlen != srclen) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Encryption failed - Cannot encrypt buffer\n");
    return 1;
    // LCOV_EXCL_STOP
  }

  return 0;
}

int AesGcm::EncryptBatch() {
  int cur = 0;

  while (progress_ + kBuffSize * kBlockSize <= src_size_) {
    /* Wait for the previous write to finish */

    if (writing_ && write_res_.get() != 0) {
      return 1;  // LCOV_EXCL_LINE
    }

    /* Read in main thread */

    if (ReadFile(buff_[cur], kBuffSize * kBlockSize)) {
      return 1;  // LCOV_EXCL_LINE
    }

    /* Encrypt in main thread */

    if (EncryptBuff(buff_[cur], buff_[cur], kBuffSize * kBlockSize)) {
      return 1;  // LCOV_EXCL_LINE
    }

    /* Asynchronous write in another thread */

    write_res_ = std::async(std::launch::async, [this, cur]() {
      return WriteFile(buff_[cur], kBuffSize * kBlockSize);
    });

    writing_ = true;

    /* Swap buffer */

    cur = 1 - cur;

    /* Update progress */

    progress_ += kBuffSize * kBlockSize;

    if (ReportProgress()) {
      write_res_.wait();
      return 1;
    }
  }

  /* Wait for the last write to finish */

  if (writing_) {
    if (write_res_.get() != 0) {
      return 1;  // LCOV_EXCL_LINE
    }

    writing_ = false;
  }

  return 0;
}

int AesGcm::EncryptRemain() {
  int crs = 0, rem = src_size_ % (kBuffSize * kBlockSize);

  if (ReadFile(buff_[0], rem)) {
    return 1;  // LCOV_EXCL_LINE
  }

  /* Encrypt remaining full blocks */

  while (progress_ + kBlockSize <= src_size_) {
    if (EncryptBuff(buff_[0][crs], buff_[0][crs], kBlockSize)) {
      return 1;  // LCOV_EXCL_LINE
    }

    crs++;

    progress_ += kBlockSize;
  }

  /* Encrypt remaining partial block */

  rem = src_size_ % kBlockSize;

  if (rem) {
    if (EncryptBuff(buff_[0][crs], buff_[0][crs], rem)) {
      return 1;  // LCOV_EXCL_LINE
    }

    progress_ += rem;
  }

  if (WriteFile(buff_[0], kBlockSize * crs + rem)) {
    return 1;  // LCOV_EXCL_LINE
  }

  if (ReportProgress()) {
    return 1;  // LCOV_EXCL_LINE
  }

  return 0;
}

int AesGcm::EncryptFinal() {
  uint8_t final[kBlockSize];
  int final_len;

  if (EVP_EncryptFinal_ex(ctx_, final, &final_len) != 1) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Finalization failed - Cannot finalize encryption\n");
    return 1;
    // LCOV_EXCL_STOP
  }

  if (final_len > 0 && WriteFile(final, final_len)) {
    return 1;  // LCOV_EXCL_LINE
  }

  return 0;
}

int AesGcm::EncryptTag() {
  uint8_t tag[kTagSize];

  if (EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_GCM_GET_TAG, kTagSize, tag) != 1) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Tag Error - Cannot get authentication tag\n");
    return 1;
    // LCOV_EXCL_STOP
  }

  if (fwrite(tag, sizeof(uint8_t), kTagSize, dst_file_) != kTagSize) {
    // LCOV_EXCL_START
    ReportError("[File] Write failed - Cannot write authentication tag on destination file\n");
    return 1;
    // LCOV_EXCL_STOP
  }

  return 0;
}