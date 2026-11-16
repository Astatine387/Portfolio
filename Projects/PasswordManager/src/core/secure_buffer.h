/**
 * @file    secure_buffer.h
 * @brief   Move-only byte buffer held in libsodium-locked memory
 * @author  Astatine387
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

/**
 * @brief   Move-only byte buffer held in libsodium-locked memory
 */
class SecureBuffer {
 public:
  SecureBuffer() = default;

  /**
   * @brief   Allocate a locked buffer of the given size
   * @param   size  Buffer size in bytes
   */
  explicit SecureBuffer(size_t size);

  ~SecureBuffer();

  SecureBuffer(const SecureBuffer&) = delete;
  SecureBuffer& operator=(const SecureBuffer&) = delete;
  SecureBuffer(SecureBuffer&& other) noexcept;
  SecureBuffer& operator=(SecureBuffer&& other) noexcept;

  /**
   * @brief   Return whether the allocation succeeded
   * @return  True if empty or allocation success
   */
  [[nodiscard]] bool Valid() const;

  /**
   * @brief   Access the buffer bytes
   * @return  Pointer to the buffer, or nullptr when empty
   */
  [[nodiscard]] uint8_t* Data();
  [[nodiscard]] const uint8_t* Data() const;

  /**
   * @brief   Return buffer size in bytes
   * @return  Buffer size in bytes
   */
  [[nodiscard]] size_t Size() const;

  /**
   * @brief   Access the buffer bytes as a span
   * @return  Span over the buffer
   */
  [[nodiscard]] std::span<uint8_t> Span();
  [[nodiscard]] std::span<const uint8_t> Span() const;

  /**
   * @brief   Access a bounds-checked subrange of the buffer
   * @param   off   Subrange offset in bytes
   * @param   len   Subrange length in bytes
   * @return  Span over the subrange, or std::nullopt when it does not fit
   */
  [[nodiscard]] std::optional<std::span<uint8_t>> Subspan(size_t off,
                                                          size_t len);
  [[nodiscard]] std::optional<std::span<const uint8_t>> Subspan(
      size_t off, size_t len) const;

  /**
   * @brief   Wipe and release the buffer
   */
  void Reset();

 private:
  uint8_t* data_ = nullptr;
  size_t size_ = 0;
};
