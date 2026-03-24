/**
 * @file	Password.cpp
 * @brief	Implementation of Password class
 * @author	Astatine387
 */

#include "Utils/library.h"
#include "Utils/Password.h"
#include <cstring>

bool Password::isEmpty() const {
	return size == 0;
}

const char *Password::getData() const {
	return data;
}

size_t Password::getSize() const {
	return size;
}

void Password::setData(const Password &pw) {
	setData(pw.getData(), pw.getSize());
}

void Password::setData(const char *str, size_t len) {
	clean();

	if (str) {
		size = len;
		data = new char[size + 1];

		Lock(data, size + 1);
		memcpy(data, str, size);

		data[size] = '\0';
	}
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