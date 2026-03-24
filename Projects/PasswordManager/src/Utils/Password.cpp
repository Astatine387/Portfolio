/**
 * @file	Password.cpp
 * @brief	Implementation of Password class
 * @author	Astatine387
 */

#include "Utils/library.h"
#include "Utils/Password.h"
#include <cstring>

bool Password::equal(const Password &other) const {
	volatile uint8_t diff = (size != other.size) ? 1 : 0;
	size_t minSize = (size < other.size) ? size : other.size;

	for (size_t i = 0; i < kMaxPWLen; i++) {
		uint8_t a = (i >= minSize) ? 0 : static_cast<uint8_t>(data[i]);
		uint8_t b = (i >= minSize) ? 0 : static_cast<uint8_t>(other.data[i]);

		diff |= a ^ b;
	}

	return diff == 0;
}

bool Password::isEmpty() const {
	return size == 0;
}

const char *Password::getData() const {
	return data;
}

size_t Password::getSize() const {
	return size;
}

int Password::setData(const Password &pw) {
	return setData(pw.getData(), pw.getSize());
}

int Password::setData(const char *str, size_t len) {
	if (len > kMaxPWLen) return 1;

	clean();

	if (str) {
		size = len;
		data = new char[size + 1];

		Lock(data, size + 1);
		memcpy(data, str, size);

		data[size] = '\0';
	}

	return 0;
}

void Password::clean() {
	if (data != nullptr) {
		Wipe(data, size + 1);
		Unlock(data, size + 1);

		delete[] data;
	}

	data = nullptr;
	size = 0;
}