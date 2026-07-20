/**
 * @file	secure_buffer.h
 * @brief	Move-only byte buffer held in libsodium-locked memory
 * @author	Astatine387
 */

#pragma once

#include <cstddef>
#include <cstdint>

/**
 * @class	SecureBuffer
 */
class SecureBuffer {
 public:
  SecureBuffer() = default;

  /**
   * @brief		Allocate a locked buffer of the given size
   * @param		size	Buffer size in bytes (0 for an empty buffer)
   */
  explicit SecureBuffer(size_t size);

  ~SecureBuffer();

  SecureBuffer(const SecureBuffer&) = delete;             // Delete copy constructor
  SecureBuffer& operator=(const SecureBuffer&) = delete;  // Delete copy assignment operator

  SecureBuffer(SecureBuffer&& other) noexcept;
  SecureBuffer& operator=(SecureBuffer&& other) noexcept;

  /**
   * @brief		Return whether the allocation succeeded
   * @return	True if empty or successfully allocated
   */
  [[nodiscard]] bool Valid() const;

  /**
   * @brief		Access the buffer bytes
   * @return	Pointer to the buffer, or nullptr when empty
   */
  [[nodiscard]] uint8_t* Data();
  [[nodiscard]] const uint8_t* Data() const;

  /**
   * @brief		Return buffer size in bytes
   * @return	Buffer size in bytes
   */
  [[nodiscard]] size_t Size() const;

  /**
   * @brief		Wipe and release the buffer
   */
  void Reset();

 private:
  uint8_t* data_ = nullptr;
  size_t size_ = 0;
};
