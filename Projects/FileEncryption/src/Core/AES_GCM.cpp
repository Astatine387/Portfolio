/**
 * @file	AES_GCM.cpp
 * @brief	Implementation of basic functions of AES_GCM class
 * @author	Astatine387
 *
 * Contents:
 *	- Implementation of destructor and helper functions of AES_GCM class
 */

#include "Core/AES_GCM.h"
#include "Utils/library.h"
#include <cstring>
#include <openssl/err.h>

AES_GCM::AES_GCM() {
	for (int i = 0; i < kBuffNum; i++) memset(buff[i], 0, sizeof(uint8_t) * kBuffSize * kBlockSize);

	memset(iv, 0, sizeof(uint8_t) * kIVSize);
	memset(salt, 0, sizeof(uint8_t) * kSaltSize);

	Lock(key, kKeySize);
}

AES_GCM::~AES_GCM() {
	if (writeRes.valid()) writeRes.wait();

	for (int i = 0; i < kBuffNum; i++) Wipe(buff[i], sizeof(uint8_t) * kBuffSize * kBlockSize);

	Wipe(iv, sizeof(uint8_t) * kIVSize);
	Wipe(key, sizeof(uint8_t) * kKeySize);
	Wipe(salt, sizeof(uint8_t) * kSaltSize);

	Unlock(key, kKeySize);

	if (ctx) {
		EVP_CIPHER_CTX_free(ctx);
		ctx = nullptr;
	}
}

int AES_GCM::readFile(void *buff, int size) {
	if (fread(buff, sizeof(uint8_t), size, src) != size) {
		// LCOV_EXCL_START
		reportError("[File] Read failed - Cannot read source file data\n");
		return 1;
		// LCOV_EXCL_STOP
	}

	return 0;
}

int AES_GCM::writeFile(const void *buff, int size) {
	if (fwrite(buff, sizeof(uint8_t), size, dst) != size) {
		// LCOV_EXCL_START
		if (ferror(dst))	reportError("[File] Write failed - Disk may be full or I/O error\n");
		else				reportError("[File] Write failed - Cannot write destination file data\n");

		return 1;
		// LCOV_EXCL_STOP
	}

	return 0;
}

int AES_GCM::reportProgress() {
	if (pcb) {
		uint64_t perc = size > 0 ? prog * 100 / size : 100;

		bool shouldCancel = false;

		pcb(perc, &shouldCancel);

		if (shouldCancel) {
			cancelled.store(true);
			return 1;
		}
	}

	return 0;
}

void AES_GCM::reportError(const char *msg) {
	if (!ecb) return;

	std::string res;
	unsigned long code;
	char errStr[256];

	res += msg;

	while ((code = ERR_get_error()) != 0) {
		ERR_error_string_n(code, errStr, sizeof(errStr));

		res += " -> ";
		res += errStr;
		res += '\n';
	}

	ecb(res.c_str());
}