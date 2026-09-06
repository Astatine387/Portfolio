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
 *
 * The bytes live in sodium_malloc memory, which is locked against the swap file and wiped on release,
 * so the lifetime of this object is the lifetime of the password in memory. Callers that are finished
 * with one assign an empty Password over it rather than waiting for the scope to end.
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

  /* Copying is refused rather than defaulted: it would put a second copy of the password in locked
   * memory, and SetData below is the one way to ask for that, where the cost is visible at the call
   * site and the allocation can be reported as having failed */

  Password(const Password&) = delete;             // Delete copy constructor
  Password& operator=(const Password&) = delete;  // Delete copy assignment operator

  /**
   * @brief     Move constructor
   * @param     other   Source password to move from
   *
   * The source is left holding nothing, so exactly one object is ever in a position to wipe the buffer.
   */
  Password(Password&& other) noexcept : size_(other.size_), data_(other.data_) {
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
   * @brief     Check whether the password is empty
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
   * @return    kSuccess on success, kFailure when secure allocation fails
   */
  [[nodiscard]] Result SetData(const Password& pw);

  /**
   * @brief     Set password data
   * @param     str     Source
   * @param     len     Password length
   * @return    kSuccess on success, kFailure when secure allocation fails
   *
   * Locked pages come out of a capped pool, so failing to get one is an ordinary outcome here rather
   * than an exceptional one, and the result is worth checking on every call.
   */
  [[nodiscard]] Result SetData(const char* str, size_t len);

 private:
  size_t size_ = 0;
  char* data_ = nullptr;  // size_ + 1 bytes in sodium_malloc memory, or nullptr when empty

  /**
   * @brief     Securely wipe password data
   */
  void Clean();
};
