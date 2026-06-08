/**
 * @file	password.h
 * @brief	RAII class that securely handles password
 * @author	Astatine387
 */

#pragma once

#include <cstddef>

#include "Common/constants.h"

/**
 * @class	Password
 * @brief	RAII class that securely handles password
 */
class Password {
 public:
  /**
   * @brief   Default constructor of Password class
   */
  Password() = default;

  /**
   * @brief   Destructor, securely wipes password data
   */
  ~Password() { Clean(); }

  /**
   * @brief   Copy constructor, performs deep copy
   * @param	other	Source password to copy
   */
  Password(const Password& other) {
    if (other.data_ && other.size_ > 0) {
      SetData(other.data_, other.size_);
    }
  }

  /**
   * @brief   Copy assignment operator, performs deep copy
   * @param	other	Source password to copy
   */
  Password& operator=(const Password& other) {
    if (this != &other) {
      Clean();

      if (other.data_ && other.size_ > 0) {
        SetData(other.data_, other.size_);
      }
    }

    return *this;
  }

  /**
   * @brief   Move constructor
   * @param	other	Source password to move from
   */
  Password(Password&& other) noexcept : data_(other.data_), size_(other.size_) {
    other.data_ = nullptr;
    other.size_ = 0;
  }

  /**
   * @brief   Move assignment operator
   * @param	other	Source password to move from
   */
  Password& operator=(Password&& other) noexcept {
    if (this != &other) {
      Clean();

      data_ = other.data_;
      size_ = other.size_;

      other.data_ = nullptr;
      other.size_ = 0;
    }

    return *this;
  }

  /**
   * @brief	Constant-time comparison with another password
   * @param	other	Password to compare
   * @return	true if equal
   */
  [[nodiscard]] bool Equal(const Password& other) const;

  /**
   * @brief   Check the password data is empty
   * @return	true if empty
   */
  [[nodiscard]] bool IsEmpty() const;

  /**
   * @brief   Get password data
   * @return	Password data
   */
  [[nodiscard]] const char* GetData() const;

  /**
   * @brief   Get password size
   * @return	Password size
   */
  [[nodiscard]] size_t GetSize() const;

  /**
   * @brief   Set password data
   * @param	pw	Source
   * @return	kSuccess on success, kFailure if password exceeds maximum length
   */
  Result SetData(const Password& pw);

  /**
   * @brief   Set password data
   * @param	str		Source
   * @param	len		Password length
   * @return	kSuccess on success, kFailure if password exceeds maximum length
   */
  Result SetData(const char* str, size_t len);

  /**
   * @brief   Securely wipe password data
   */
  void Clean();

 private:
  char* data_ = nullptr;
  size_t size_ = 0;
};