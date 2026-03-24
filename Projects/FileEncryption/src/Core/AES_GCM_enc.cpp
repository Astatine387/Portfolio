/**
 * @file	AES_GCM_enc.cpp
 * @brief	Implementation of encryption function of AES_GCM class
 * @author	Astatine387
 */

#include "Core/AES_GCM.h"
#include "Utils/library.h"

int AES_GCM::encrypt(FILE *src, FILE *dst, const char *pw, size_t plen) {
	this->src = src;
	this->dst = dst;
	cancelled = false;
	prog = 0;

	writing = false;

	if (encryptInit(pw, plen)) return 1;

	if (encryptBatch()) return 1;

	if (encryptRemain()) return 1;

	if (encryptFinal()) return 1;

	if (encryptTag()) return 1;

	return 0;
}

int AES_GCM::encryptInit(const char *pw, size_t plen) {
	/* Clear existing context */

	if (ctx) {
		EVP_CIPHER_CTX_free(ctx);
		ctx = nullptr;
	}


	/* Get source file size */

	size = GetFileSize(src);
	
	if (size == -1) {
		// LCOV_EXCL_START
		reportError("[File] Size check failed - Cannot read source file size\n");
		return 1;
		// LCOV_EXCL_STOP
	}

	if (size > kMaxSize) {
		// LCOV_EXCL_START
		reportError("[File] Validation failed - File should be at most 64 GiB\n");
		return 1;
		// LCOV_EXCL_STOP
	}


	/* Generate salt and IV */

	if (Random(salt, kSaltSize)) {
		// LCOV_EXCL_START
		reportError("[Crypto] Random failed - Cannot generate salt\n");
		return 1;
		// LCOV_EXCL_STOP
	}

	if (Random(iv, kIVSize)) {
		// LCOV_EXCL_START
		reportError("[Crypto] Random failed - Cannot generate initial vector\n");
		return 1;
		// LCOV_EXCL_STOP
	}


	/* Derive key from password */

	if (Argon2id(salt, pw, plen, key)) {
		// LCOV_EXCL_START
		reportError("[Crypto] Key derivation failed - Argon2id error\n");
		return 1;
		// LCOV_EXCL_STOP
	}


	/* Set encryption context */

	if (!(ctx = EVP_CIPHER_CTX_new())) {
		// LCOV_EXCL_START
		reportError("[Crypto] Initialization failed - Cannot create context\n");
		return 1;
		// LCOV_EXCL_STOP
	}

	if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
		// LCOV_EXCL_START
		reportError("[Crypto] Initialization failed - Cannot set AES-256-GCM algorithm\n");
		return 1;
		// LCOV_EXCL_STOP
	}

	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, kIVSize, NULL) != 1) {
		// LCOV_EXCL_START
		reportError("[Crypto] Initialization failed - Cannot set initial vector size\n");
		return 1;
		// LCOV_EXCL_STOP
	}

	if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
		// LCOV_EXCL_START
		reportError("[Crypto] Initialization failed - Cannot set key and initial vector\n");
		return 1;
		// LCOV_EXCL_STOP
	}


	/* Write salt and IV */

	if (fwrite(salt, sizeof(uint8_t), kSaltSize, dst) != kSaltSize) {
		// LCOV_EXCL_START
		reportError("[File] Write failed - Cannot write salt to destination file header\n");
		return 1;
		// LCOV_EXCL_STOP
	}

	if (fwrite(iv, sizeof(uint8_t), kIVSize, dst) != kIVSize) {
		// LCOV_EXCL_START
		reportError("[File] Write failed - Cannot write initial vector to destination file header\n");
		return 1;
		// LCOV_EXCL_STOP
	}


	return 0;
}

int AES_GCM::encryptBuff(void *src, void *dst, int srcLen) {
	int dstLen;
	
	if (EVP_EncryptUpdate(ctx, static_cast<unsigned char *>(dst), &dstLen, static_cast<unsigned char *>(src), srcLen) != 1) {
		// LCOV_EXCL_START
		reportError("[Crypto] Encryption failed - Cannot encrypt buffer\n");
		return 1;
		// LCOV_EXCL_STOP
	}

	if (dstLen != srcLen) {
		// LCOV_EXCL_START
		reportError("[Crypto] Encryption failed - Cannot encrypt buffer\n");
		return 1;
		// LCOV_EXCL_STOP
	}

	return 0;
}

int AES_GCM::encryptBatch() {
	int cur = 0;

	while (prog + kBuffSize * kBlockSize <= size) {
		/* Wait for the previous write to finish */

		if (writing && writeRes.get() != 0) return 1;


		/* Read in main thread */

		if (readFile(buff[cur], kBuffSize * kBlockSize)) return 1;


		/* Encrypt in main thread */

		if (encryptBuff(buff[cur], buff[cur], kBuffSize * kBlockSize)) return 1;


		/* Asynchronous write in another thread */

		writeRes = std::async(std::launch::async, [this, cur]() {
			return writeFile(buff[cur], kBuffSize * kBlockSize);
		});

		writing = true;


		/* Swap buffer */

		cur = 1 - cur;


		/* Update progress */

		prog += kBuffSize * kBlockSize;

		if (reportProgress()) {
			writeRes.wait();
			return 1;
		}
	}


	/* Wait for the last write to finish */

	if (writing) {
		if (writeRes.get() != 0) return 1;

		writing = false;
	}

	return 0;
}

int AES_GCM::encryptRemain() {
	int crs = 0, rem = size % (kBuffSize * kBlockSize);

	if (readFile(buff[0], rem)) return 1;


	/* Encrypt remaining full blocks */

	while (prog + kBlockSize <= size) {
		if (encryptBuff(buff[0][crs], buff[0][crs], kBlockSize)) return 1;

		crs++;

		prog += kBlockSize;
	}


	/* Encrypt remaining partial block */

	rem = size % kBlockSize;

	if (rem) {
		if (encryptBuff(buff[0][crs], buff[0][crs], rem)) return 1;

		prog += rem;
	}

	if (writeFile(buff[0], kBlockSize * crs + rem)) return 1;


	if (reportProgress()) return 1;

	return 0;
}

int AES_GCM::encryptFinal() {
	uint8_t final[kBlockSize];
	int finalLen;
	
	if (EVP_EncryptFinal_ex(ctx, final, &finalLen) != 1) {
		// LCOV_EXCL_START
		reportError("[Crypto] Finalization failed - Cannot finalize encryption\n");
		return 1;
		// LCOV_EXCL_STOP
	}

	if (finalLen > 0 && writeFile(final, finalLen)) return 1;

	return 0;
}

int AES_GCM::encryptTag() {
	uint8_t tag[kTagSize];
	
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, kTagSize, tag) != 1) {
		// LCOV_EXCL_START
		reportError("[Crypto] Tag Error - Cannot get authentication tag\n");
		return 1;
		// LCOV_EXCL_STOP
	}

	if (fwrite(tag, sizeof(uint8_t), kTagSize, dst) != kTagSize) {
		// LCOV_EXCL_START
		reportError("[File] Write failed - Cannot write authentication tag on destination file\n");
		return 1;
		// LCOV_EXCL_STOP
	}

	return 0;
}