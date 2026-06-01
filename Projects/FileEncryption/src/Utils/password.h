/**
 * @file	password.h
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
  Password(Password&& other) noexcept : data_(other.data_), size_(other.size_), locked_(other.locked_) {
    other.data_ = nullptr;
    other.size_ = 0;
    other.locked_ = false;
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
      locked_ = other.locked_;

      other.data_ = nullptr;
      other.size_ = 0;
      other.locked_ = false;
    }

    return *this;
  }

  /**
   * @brief   Check whether the password is empty
   * @return	true if empty
   */
  bool IsEmpty() const;

  /**
   * @brief   Check whether the password is locked in memory
   * @return  true if locked
   */
  bool IsLocked() const;

  /**
   * @brief   Get password data
   * @return	Password data
   */
  const char* GetData() const;

  /**
   * @brief   Get password size
   * @return	Password size
   */
  size_t GetSize() const;

  /**
   * @brief   Set password data
   * @param	pw	Source
   */
  void SetData(const Password& pw);

  /**
   * @brief   Set password data
   * @param	str		Source
   * @param	len		Password length
   */
  void SetData(const char* str, size_t len);

 private:
  size_t size_ = 0;
  char* data_ = nullptr;
  bool locked_ = false;

  /**
   * @brief   Securely wipe password data
   */
  void Clean();
};