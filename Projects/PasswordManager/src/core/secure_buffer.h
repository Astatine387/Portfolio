/**
 * @file	secure_buffer.h
 * @brief	Move-only byte buffer held in libsodium-locked memory
 * @author	Astatine387
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

/**
 * @class   SecureBuffer
 * @brief   Move-only byte buffer held in libsodium-locked memory
 *
 * The bytes come from sodium_malloc, and what stands around them is libsodium's rather than this class's: a
 * guard page on either side of the allocation, and a canary in front of the returned pointer that sodium_free
 * checks when the region is released, aborting the process when it has been overwritten. Nothing here inspects
 * either of them and no member reports on them, so the size and the spans below describe the bytes the caller
 * asked for and nothing beside them.
 */
class SecureBuffer {
 public:
  SecureBuffer() = default;

  /**
   * @brief   Allocate a locked buffer of the given size
   * @param   size  Buffer size in bytes (0 for an empty buffer)
   */
  explicit SecureBuffer(size_t size);

  ~SecureBuffer();

  SecureBuffer(const SecureBuffer&) = delete;             // Delete copy constructor
  SecureBuffer& operator=(const SecureBuffer&) = delete;  // Delete copy assignment operator

  SecureBuffer(SecureBuffer&& other) noexcept;
  SecureBuffer& operator=(SecureBuffer&& other) noexcept;

  /**
   * @brief   Return whether the allocation succeeded
   * @return  True if empty or successfully allocated
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
   * @return  Span over the buffer (empty when the buffer is empty)
   */
  [[nodiscard]] std::span<uint8_t> Span();
  [[nodiscard]] std::span<const uint8_t> Span() const;

  /**
   * @brief   Access a bounds-checked subrange of the buffer
   * @param   off   Offset of the subrange in bytes
   * @param   len   Length of the subrange in bytes
   * @return  Span over the subrange, or std::nullopt when it does not fit
   */
  [[nodiscard]] std::optional<std::span<uint8_t>> Subspan(size_t off, size_t len);
  [[nodiscard]] std::optional<std::span<const uint8_t>> Subspan(size_t off, size_t len) const;

  /**
   * @brief   Wipe and release the buffer
   */
  void Reset();

 private:
  uint8_t* data_ = nullptr;
  size_t size_ = 0;
};
