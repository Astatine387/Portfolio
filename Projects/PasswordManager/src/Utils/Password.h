/**
 * @file	Password.h
 * @brief	RAII class that securely handles password
 * @author	Astatine387
 */

#pragma once

#include <cstddef>

/**
 * @class	Password
 * @brief	RAII class that securely handles password
 */
class Password {
public:
	/**
	 * @brief   Default constructor of Password class
	 */
	Password() {
		;
	}

	/**
	 * @brief   Destructor, securely wipes password data
	 */
	~Password() {
		clean();
	}

	/**
	 * @brief   Copy constructor, performs deep copy
	 * @param	other	Source password to copy
	 */
	Password(const Password &other) {
		if (other.data && other.size > 0) setData(other.data, other.size);
	}

	/**
	 * @brief   Copy assignment operator, performs deep copy
	 * @param	other	Source password to copy
	 */
	Password &operator=(const Password &other) {
		if (this != &other) {
			clean();

			if (other.data && other.size > 0) setData(other.data, other.size);
		}

		return *this;
	}

	/**
	 * @brief   Move constructor
	 * @param	other	Source password to copy
	 */
	Password(Password &&other) noexcept : data(other.data), size(other.size) {
		other.data = nullptr;
		other.size = 0;
	}

	/**
	 * @brief   Move assignment constructor
	 * @param	other	Source password to copy
	 */
	Password &operator=(Password &&other) noexcept {
		if (this != &other) {
			clean();

			data = other.data;
			size = other.size;

			other.data = nullptr;
			other.size = 0;
		}

		return *this;
	}

	/**
	 * @brief	Constant-time comparison with another password
	 * @param	other	Password to compare
	 * @return	true if equal
	 */
	bool equal(const Password &other) const;

	/**
	 * @brief   Check the password data is empty
	 * @return	true if empty
	 */
	bool isEmpty() const;

	/**
	 * @brief   Get password data
	 * @return	Password data
	 */
	const char *getData() const;

	/**
	 * @brief   Get password size
	 * @return	Password size
	 */
	size_t getSize() const;

	/**
	 * @brief   Set password data
	 * @param	pw	Source
	 */
	int setData(const Password &pw);

	/**
	 * @brief   Set password data
	 * @param	str		Source
	 * @param	len		Password length
	 */
	int setData(const char *str, size_t len);

	/**
	 * @brief   Securely wipe password data
	 */
	void clean();

private:
	char *data = nullptr;
	size_t size = 0;
};