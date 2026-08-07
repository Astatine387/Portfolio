/**
 * @file	password.h
 * @brief	RAII class that securely handles password
 * @author	Astatine387
 */

#pragma once

#include <cstddef>

#include "common/constants.h"

/**
 * @class   Password
 * @brief   RAII class that securely handles password
 */
class Password {
 public:
  /**
   * @brief     Default constructor of Password class
   */
  Password() = default;

  /**
   * @brief     Destructor, securely wipes password data
   */
  ~Password() { Clean(); }

  Password(const Password&) = delete;             // Delete copy constructor
  Password& operator=(const Password&) = delete;  // Delete copy assignment operator

  /**
   * @brief     Move constructor
   * @param     other   Source password to move from
   */
  Password(Password&& other) noexcept : data_(other.data_), size_(other.size_) {
    other.data_ = nullptr;
    other.size_ = 0;
  }

  /**
   * @brief     Move assignment operator
   * @param     other   Source password to move from
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
   * @brief     Constant-time comparison with another password
   * @param     other   Password to compare
   * @return    true if equal
   */
  [[nodiscard]] bool Equal(const Password& other) const;

  /**
   * @brief     Check the password data is empty
   * @return    true if empty
   */
  [[nodiscard]] bool IsEmpty() const;

  /**
   * @brief     Get password data
   * @return    Password data
   */
  [[nodiscard]] const char* GetData() const;

  /**
   * @brief     Get password size
   * @return    Password size
   */
  [[nodiscard]] size_t GetSize() const;

  /**
   * @brief     Set password data
   * @param     pw  Source
   * @return    kSuccess on success, kFailure if password exceeds maximum length
   */
  [[nodiscard]] Result SetData(const Password& pw);

  /**
   * @brief     Set password data
   * @param     str     Source
   * @param     len     Password length
   * @return    kSuccess on success, kFailure if password exceeds maximum length
   */
  [[nodiscard]] Result SetData(const char* str, size_t len);

  /**
   * @brief     Securely wipe password data
   */
  void Clean();

 private:
  char* data_ = nullptr;  // kMaxPWLen + 1 bytes in sodium_malloc memory, or nullptr when empty
  size_t size_ = 0;
};
