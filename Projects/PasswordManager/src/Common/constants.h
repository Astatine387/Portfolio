/**
 * @file	constants.h
 * @brief	Header file for constants
 * @author	Astatine387
 */

#pragma once

#include <cstdint>
#include <cstddef>

inline constexpr double kFontScale = 1.2; /// GUI font scale

inline constexpr size_t kKeySize  = 32;         /// AES-GCM key size in bytes
inline constexpr size_t kSaltSize = 16;         /// Argon2id salt size in bytes
inline constexpr int	kMemCost  = 512 * 1024; /// Argon2id memory cost in KiB
inline constexpr int	kTimeCost = 4;          /// Argon2id time cost 

inline constexpr size_t kBlockSize = 16; /// AES-GCM block size in bytes
inline constexpr size_t kIVSize    = 12; /// Initial vector size in bytes
inline constexpr size_t kTagSize   = 16; /// Authentication tag size in bytes

inline constexpr uint32_t kMagicNum	 = 0x63a5baf3;       /// Magic number to distinguish vault file
inline constexpr int	  kMagicSize = 4;                /// Magic number size
inline constexpr size_t   kCountSize = sizeof(uint32_t); /// Entry count field size

inline constexpr int64_t kMaxSize = 2ULL * 1024 * 1024 * 1024;									/// Maximum vault file size
inline constexpr int64_t kMinSize = (kMagicSize + kSaltSize + kIVSize + kCountSize + kTagSize);	/// Mininum vault file size

inline constexpr int kMaxSiteLen = 256;	/// Maximum length of site name
inline constexpr int kMaxAccLen  = 256;	/// Maximum length of account
inline constexpr int kMaxPWLen   = 256;	/// Maximum length of password

inline constexpr size_t kMinEntrySize = (sizeof(uint32_t) + 1) * 3; // Minimum serialized entry size
