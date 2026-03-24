/**
 * @file	AES_GCM_enc.cpp
 * @brief	Implementation of encryption functions AES_GCM class
 * @author	Astatine387
 */

#include "Core/AES_GCM.h"
#include "Utils/library.h"
#include <cstring>

int AES_GCM::encrypt(uint8_t *src, uint8_t *dst, size_t size, const char *pw, size_t plen) {
	this->src = src, this->dst = dst, this->size = size;
	srcCrs = 0, dstCrs = 0;

	if (encryptInit(pw, plen)) return 1;

	if (encryptBuff()) return 1;

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

	memcpy(dst + dstCrs, salt, kSaltSize);
	dstCrs += kSaltSize;

	memcpy(dst + dstCrs, iv, kIVSize);
	dstCrs += kIVSize;


	return 0;
}

int AES_GCM::encryptBuff() {
	int outLen;

	if (EVP_EncryptUpdate(ctx, dst + dstCrs, &outLen, src, size) != 1) {
		// LCOV_EXCL_START
		reportError("[Crypto] Encryption failed - Cannot encrypt buffer\n");
		return 1;
		// LCOV_EXCL_STOP
	}

	if (outLen != size) {
		// LCOV_EXCL_START
		reportError("[Crypto] Encryption failed - Cannot encrypt buffer\n");
		return 1;
		// LCOV_EXCL_STOP
	}

	dstCrs += size;

	return 0;
}

int AES_GCM::encryptFinal() {
	uint8_t finalBuff[kBlockSize];
	int finalLen;

	if (EVP_EncryptFinal_ex(ctx, finalBuff, &finalLen) != 1) {
		// LCOV_EXCL_START
		reportError("[Crypto] Finalization failed - Cannot finalize encryption\n");
		return 1;
		// LCOV_EXCL_STOP
	}

	if (finalLen > 0) {
		// LCOV_EXCL_START
		reportError("[Crypto] Finalization failed - Unexpected output from finalization\n");
		return 1;
		// LCOV_EXCL_STOP
	}

	memcpy(dst + dstCrs, finalBuff, finalLen);
	dstCrs += finalLen;

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

	memcpy(dst + dstCrs, tag, kTagSize);
	dstCrs += kTagSize;

	return 0;
}