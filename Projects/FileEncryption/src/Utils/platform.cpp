/**
 * @file	platform.cpp
 * @brief	Implementation of common utility functions
 * @author	Astatine387
 */

#include "Utils/platform.h"

#include <argon2.h>

#include "Common/constants.h"

Result Argon2id(uint8_t* salt, const char* pw, size_t plen, uint8_t* key) {
  if (argon2id_hash_raw(kTimeCost, kMemCost, kParallelism, pw, plen, salt, kSaltSize, key, kKeySize) != ARGON2_OK) {
    return Result::kFailure;  // LCOV_EXCL_LINE
  }

  return Result::kSuccess;
}