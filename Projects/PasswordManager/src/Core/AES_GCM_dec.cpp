/**
 * @file	AES_GCM_dec.cpp
 * @brief	Implementation of decryption functions AES_GCM class
 * @author	Astatine387
 */

#include "Core/AES_GCM.h"
#include "Utils/library.h"
#include <cstring>

int AES_GCM::decrypt(uint8_t *src, uint8_t *dst, size_t size, const char *pw, size_t plen) {
	this->src = src, this->dst = dst, this->size = size;
	srcCrs = 0, dstCrs = 0;

	if (decryptInit(pw, plen)) return 1;

	if (decryptTag()) return 1;

	if (decryptBuff()) return 1;

	if (decryptFinal()) return 1;

	return 0;
}

int AES_GCM::decryptInit(const char *pw, size_t plen) {
	/* Clear existing context */

	if (ctx) {
		EVP_CIPHER_CTX_free(ctx);
		ctx = nullptr;
	}


	/* Read salt and IV */

	memcpy(salt, src + srcCrs, kSaltSize);
	srcCrs += kSaltSize;

	memcpy(iv, src + srcCrs, kIVSize);
	srcCrs += kIVSize;


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

	memcpy(tag, src + size - kTagSize, kTagSize);

	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, kTagSize, tag) != 1) {
		// LCOV_EXCL_START
		reportError("[Crypto] Tag failed - Cannot set authentication tag\n");
		return 1;
		// LCOV_EXCL_STOP
	}

	return 0;
}

int AES_GCM::decryptBuff() {
	int inLen = size - kSaltSize - kIVSize - kTagSize;
	int outLen;

	if (EVP_DecryptUpdate(ctx, dst, &outLen, src + srcCrs, inLen) != 1) {
		// LCOV_EXCL_START
		reportError("[Crypto] Decryption failed - Cannot decrypt buffer\n");
		return 1;
		// LCOV_EXCL_STOP
	}

	if (outLen != inLen) {
		// LCOV_EXCL_START
		reportError("[Crypto] Decryption failed - Cannot decrypt buffer\n");
		return 1;
		// LCOV_EXCL_STOP
	}

	dstCrs += inLen;

	return 0;
}

int AES_GCM::decryptFinal() {
	uint8_t finalBuff[kBlockSize];
	int finalLen;

	if (EVP_DecryptFinal_ex(ctx, finalBuff, &finalLen) != 1) {
		// LCOV_EXCL_START
		reportError("[Crypto] Finalization failed - Cannot finalize decryption\n");
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