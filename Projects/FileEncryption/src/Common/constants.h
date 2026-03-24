/**
 * @file	constants.h
 * @brief	Header file for constants
 * @author	Astatine387
 */

#pragma once

#include <cstdint>
#include <cstddef>

inline constexpr double kFontScale	= 1.2;	/// GUI font scale

inline constexpr size_t kKeySize	= 32;			/// AES-GCM key size in bytes
inline constexpr size_t kSaltSize	= 16;			/// Argon2id salt size in bytes
inline constexpr int	kMemCost	= 512 * 1024;	/// Argon2id memory cost in KiB
inline constexpr int	kTimeCost	= 4;			/// Argon2id time cost 

inline constexpr size_t kBlockSize	= 16;		/// AES-GCM block size in bytes
inline constexpr int	kBuffNum	= 2;		/// Number of buffers for swapping
inline constexpr size_t kBuffSize	= 4096;		/// Buffer size in blocks
inline constexpr size_t kIVSize		= 12;		/// Initial vector size in bytes
inline constexpr size_t kTagSize	= 16;		/// Authentication tag size in bytes

inline constexpr int64_t kMaxSize = 64ULL * 1024 * 1024 * 1024;		/// Maximum source file size that can be processed
