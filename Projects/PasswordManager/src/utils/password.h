/**
 * @file    password.h
 * @brief   RAII class that securely handles password
 * @author  Astatine387
 */

#pragma once

#include <cstddef>

#include "common/constants.h"

/**
 * @brief   RAII class that securely handles password
 */
class Password {
 public:
  /**
   * @brief   Constructor of Password class
   *
   * Using default constructor.
   */
  Password() = default;

  /**
   * @brief   Destructor of Password class
   *
   * Securely wipes password data.
   */
  ~Password() { Clean(); }

  Password(const Password&) = delete;             // Delete copy constructor
  Password& operator=(const Password&) = delete;  // Delete copy assignment

  /**
   * @brief   Move constructor
   * @param   src   Password to move from
   *
   * The buffer moves over and the source is left empty, so that only one
   * object at a time holds the password data.
   */
  Password(Password&& src) noexcept : data_(src.data_), size_(src.size_) {
    src.data_ = nullptr;
    src.size_ = 0;
  }

  /**
   * @brief   Move assignment
   * @param   src   Password to move from
   *
   * The current password is wiped first, then the buffer moves over and the
   * source is left empty, so that only one object at a time holds the password
   * data.
   */
  Password& operator=(Password&& src) noexcept {
    if (this != &src) {
      Clean();

      data_ = src.data_;
      size_ = src.size_;

      src.data_ = nullptr;
      src.size_ = 0;
    }

    return *this;
  }

  /**
   * @brief   Constant-time comparison with another password
   * @param   other  Password to compare against
   * @return  true if the passwords are equal
   */
  [[nodiscard]] bool Equal(const Password& other) const;

  /**
   * @brief   Check whether the password is empty
   * @return  true if empty, false if not empty
   */
  [[nodiscard]] bool IsEmpty() const;

  /**
   * @brief   Get password data
   * @return  Password data
   */
  [[nodiscard]] const char* GetData() const;

  /**
   * @brief   Get password size
   * @return  Password size
   */
  [[nodiscard]] size_t GetSize() const;

  /**
   * @brief   Set password data from another Password
   * @param   pw  Source
   * @return  kSuccess on success, kFailure when the password exceeds
   * kMaxMasterPwLen or secure allocation fails
   */
  [[nodiscard]] Result SetData(const Password& pw);

  /**
   * @brief   Set password data from C string
   * @param   str   Source
   * @param   len   Password length
   * @return  kSuccess on success, kFailure when the password exceeds
   * kMaxMasterPwLen or secure allocation fails
   *
   * On failure the current password is left as it was.
   */
  [[nodiscard]] Result SetData(const char* str, size_t len);

  /**
   * @brief   Wipe password data
   */
  void Clean();

 private:
  char* data_ = nullptr;
  size_t size_ = 0;
};
