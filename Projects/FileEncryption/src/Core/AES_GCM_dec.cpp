/**
 * @file	AES_GCM_dec.cpp
 * @brief	Implementation of decryption function of AES_GCM class
 * @author	Astatine387
 */

#include "Core/AES_GCM.h"
#include "Utils/library.h"

int AES_GCM::Decrypt(FILE* src, FILE* dst, const char* pw, size_t plen) {
  src_file_ = src;
  dst_file_ = dst;
  cancelled_ = false;
  progress_ = 0;
  writing_ = false;

  if (DecryptInit(pw, plen)) {
    return 1;  // LCOV_EXCL_LINE
  }

  if (DecryptTag()) {
    return 1;  // LCOV_EXCL_LINE
  }

  if (DecryptBatch()) {
    return 1;  // LCOV_EXCL_LINE
  }

  if (DecryptRemain()) {
    return 1;  // LCOV_EXCL_LINE
  }

  if (DecryptFinal()) {
    return 1;  // LCOV_EXCL_LINE
  }

  return 0;
}

int AES_GCM::DecryptInit(const char* pw, size_t plen) {
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

  if (src_size_ < kSaltSize + kIVSize + kTagSize) {
    // LCOV_EXCL_START
    ReportError("[File] Validation failed - File should be at least 44 bytes\n");
    return 1;
    // LCOV_EXCL_STOP
  }

  src_size_ -= kSaltSize + kIVSize + kTagSize;

  /* Read salt and IV */

  if (fread(salt_, sizeof(uint8_t), kSaltSize, src_file_) != kSaltSize) {
    // LCOV_EXCL_START
    ReportError("[File] Read failed - Cannot read salt from source file header\n");
    return 1;
    // LCOV_EXCL_STOP
  }

  if (fread(iv_, sizeof(uint8_t), kIVSize, src_file_) != kIVSize) {
    // LCOV_EXCL_START
    ReportError("[File] Read failed - Cannot read initial vector from source file header\n");
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

  /* Set decryption context */

  if (!(ctx_ = EVP_CIPHER_CTX_new())) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Initialization failed - Cannot create context\n");
    return 1;
    // LCOV_EXCL_STOP
  }

  if (EVP_DecryptInit_ex(ctx_, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
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

  if (EVP_DecryptInit_ex(ctx_, NULL, NULL, key_, iv_) != 1) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Initialization failed - Cannot set key and initial vector\n");
    return 1;
    // LCOV_EXCL_STOP
  }

  return 0;
}

int AES_GCM::DecryptTag() {
  uint8_t tag[kTagSize];

  if (Seek(src_file_, -kTagSize, SEEK_END)) {
    // LCOV_EXCL_START
    ReportError("[File] Seek failed - Cannot move file pointer to authentication tag\n");
    return 1;
    // LCOV_EXCL_STOP
  }

  if (fread(tag, sizeof(uint8_t), kTagSize, src_file_) != kTagSize) {
    // LCOV_EXCL_START
    ReportError("[File] Read failed - Cannot read authentication tag\n");
    return 1;
    // LCOV_EXCL_STOP
  }

  if (EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_GCM_SET_TAG, kTagSize, tag) != 1) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Tag failed - Cannot set authentication tag\n");
    return 1;
    // LCOV_EXCL_STOP
  }

  if (Seek(src_file_, kSaltSize + kIVSize, SEEK_SET)) {
    // LCOV_EXCL_START
    ReportError("[File] Seek failed - Cannot move file pointer to data\n");
    return 1;
    // LCOV_EXCL_STOP
  }

  return 0;
}

int AES_GCM::DecryptBuff(void* src, void* dst, int srclen) {
  int dstlen;

  if (EVP_DecryptUpdate(ctx_, static_cast<unsigned char*>(dst), &dstlen,
                        static_cast<unsigned char*>(src), srclen) != 1) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Decryption failed - Cannot decrypt block\n");
    return 1;
    // LCOV_EXCL_STOP
  }

  if (dstlen != srclen) {
    // LCOV_EXCL_START
    ReportError("[Crypto] Decryption failed - Cannot decrypt block\n");
    return 1;
    // LCOV_EXCL_STOP
  }

  return 0;
}

int AES_GCM::DecryptBatch() {
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

    /* Decrypt in main thread */

    if (DecryptBuff(buff_[cur], buff_[cur], kBuffSize * kBlockSize)) {
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

int AES_GCM::DecryptRemain() {
  int crs = 0, rem = src_size_ % (kBuffSize * kBlockSize);

  if (ReadFile(buff_[0], rem)) {
    return 1;  // LCOV_EXCL_LINE
  }

  /* Decrypt remaining full blocks */

  while (progress_ + kBlockSize <= src_size_) {
    if (DecryptBuff(buff_[0][crs], buff_[0][crs], kBlockSize))
      return 1;

    crs++;

    progress_ += kBlockSize;
  }

  /* Decrypt remaining partial block */

  rem = src_size_ % kBlockSize;

  if (rem) {
    if (DecryptBuff(buff_[0][crs], buff_[0][crs], rem)) {
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

int AES_GCM::DecryptFinal() {
  uint8_t final[kBlockSize];
  int final_len;

  if (EVP_DecryptFinal_ex(ctx_, final, &final_len) != 1) {
    ReportError("[Auth] Verification failed - Invalid password or corrupted file\n");
    return 1;
  }

  if (final_len > 0 && WriteFile(final, final_len)) {
    return 1;  // LCOV_EXCL_LINE
  }

  return 0;
}