/**
 * @file	AES_GCM_dec.cpp
 * @brief	Implementation of decryption function of AES_GCM class
 * @author	Astatine387
 */

#include "Core/AES_GCM.h"
#include "Utils/library.h"

int AES_GCM::decrypt(FILE *src, FILE *dst, const char *pw, size_t plen) {
	this->src = src;
	this->dst = dst;
	cancelled = false;
	prog = 0;

	writing = false;

	if (decryptInit(pw, plen)) return 1;

	if (decryptTag()) return 1;

	if (decryptBatch()) return 1;

	if (decryptRemain()) return 1;

	if (decryptFinal()) return 1;

	return 0;
}

int AES_GCM::decryptInit(const char *pw, size_t plen) {
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

	if (size < kSaltSize + kIVSize + kTagSize) {
		// LCOV_EXCL_START
		reportError("[File] Validation failed - File should be at least 44 bytes\n");
		return 1;
		// LCOV_EXCL_STOP
	}

	size -= kSaltSize + kIVSize + kTagSize;


	/* Read salt and IV */

	if (fread(salt, sizeof(uint8_t), kSaltSize, src) != kSaltSize) {
		// LCOV_EXCL_START
		reportError("[File] Read failed - Cannot read salt from source file header\n");
		return 1;
		// LCOV_EXCL_STOP
	}

	if (fread(iv, sizeof(uint8_t), kIVSize, src) != kIVSize) {
		// LCOV_EXCL_START
		reportError("[File] Read failed - Cannot read initial vector from source file header\n");
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


	/* Set decryption context */
	
	if (!(ctx = EVP_CIPHER_CTX_new())) {
		// LCOV_EXCL_START
		reportError("[Crypto] Initialization failed - Cannot create context\n");
		return 1;
		// LCOV_EXCL_STOP
	}

	if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
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

	if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
		// LCOV_EXCL_START
		reportError("[Crypto] Initialization failed - Cannot set key and initial vector\n");
		return 1;
		// LCOV_EXCL_STOP
	}


	return 0;
}

int AES_GCM::decryptTag() {
	uint8_t tag[kTagSize];

	if (Seek(src, -kTagSize, SEEK_END)) {
		// LCOV_EXCL_START
		reportError("[File] Seek failed - Cannot move file pointer to authentication tag\n");
		return 1;
		// LCOV_EXCL_STOP
	}

	if (fread(tag, sizeof(uint8_t), kTagSize, src) != kTagSize) {
		// LCOV_EXCL_START
		reportError("[File] Read failed - Cannot read authentication tag\n");
		return 1;
		// LCOV_EXCL_STOP
	}

	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, kTagSize, tag) != 1) {
		// LCOV_EXCL_START
		reportError("[Crypto] Tag failed - Cannot set authentication tag\n");
		return 1;
		// LCOV_EXCL_STOP
	}

	if (Seek(src, kSaltSize + kIVSize, SEEK_SET)) {
		// LCOV_EXCL_START
		reportError("[File] Seek failed - Cannot move file pointer to data\n");
		return 1;
		// LCOV_EXCL_STOP
	}

	return 0;
}

int AES_GCM::decryptBuff(void *src, void *dst, int srcLen) {
	int dstLen;
	
	if (EVP_DecryptUpdate(ctx, static_cast<unsigned char *>(dst), &dstLen, static_cast<unsigned char *>(src), srcLen) != 1) {
		// LCOV_EXCL_START
		reportError("[Crypto] Decryption failed - Cannot decrypt block\n");
		return 1;
		// LCOV_EXCL_STOP
	}

	if (dstLen != srcLen) {
		// LCOV_EXCL_START
		reportError("[Crypto] Decryption failed - Cannot decrypt block\n");
		return 1;
		// LCOV_EXCL_STOP
	}

	return 0;
}

int AES_GCM::decryptBatch() {
	int cur = 0;

	while (prog + kBuffSize * kBlockSize <= size) {
		/* Wait for the previous write to finish */

		if (writing && writeRes.get() != 0) return 1;
		
		
		/* Read in main thread */

		if (readFile(buff[cur], kBuffSize * kBlockSize)) return 1;


		/* Decrypt in main thread */

		if (decryptBuff(buff[cur], buff[cur], kBuffSize * kBlockSize)) return 1;


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

int AES_GCM::decryptRemain() {
	int crs = 0, rem = size % (kBuffSize * kBlockSize);

	if (readFile(buff[0], rem)) return 1;


	/* Decrypt remaining full blocks */

	while (prog + kBlockSize <= size) {
		if (decryptBuff(buff[0][crs], buff[0][crs], kBlockSize)) return 1;

		crs++;

		prog += kBlockSize;
	}


	/* Decrypt remaining partial block */

	rem = size % kBlockSize;

	if (rem) {
		if (decryptBuff(buff[0][crs], buff[0][crs], rem)) return 1;

		prog += rem;
	}

	if (writeFile(buff[0], kBlockSize * crs + rem)) return 1;


	if (reportProgress()) return 1;

	return 0;
}

int AES_GCM::decryptFinal() {
	uint8_t final[kBlockSize];
	int finalLen;

	if (EVP_DecryptFinal_ex(ctx, final, &finalLen) != 1) {
		reportError("[Auth] Verification failed - Invalid password or corrupted file\n");
		return 1;
	}

	if (finalLen > 0 && writeFile(final, finalLen)) return 1;  // LCOV_EXCL_LINE

	return 0;
}