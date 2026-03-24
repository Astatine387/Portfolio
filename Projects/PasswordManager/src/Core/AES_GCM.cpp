/**
 * @file	AES_GCM.cpp
 * @brief	Implementation of basic functions AES_GCM class
 * @author	Astatine387
 */

#include "Core/AES_GCM.h"
#include "Utils/library.h"
#include <cstring>
#include <openssl/err.h>

AES_GCM::AES_GCM() {
	memset(iv, 0, sizeof(uint8_t) * kIVSize);
	memset(salt, 0, sizeof(uint8_t) * kSaltSize);

	Lock(key, kKeySize);
}

AES_GCM::~AES_GCM() {
	Wipe(iv, sizeof(uint8_t) * kIVSize);
	Wipe(key, sizeof(uint8_t) * kKeySize);
	Wipe(salt, sizeof(uint8_t) * kSaltSize);

	Unlock(key, kKeySize);

	if (ctx) {
		EVP_CIPHER_CTX_free(ctx);
		ctx = nullptr;
	}
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