/**
 * @file	platform.cpp
 * @brief	Implementation of common utility functions
 * @author	Astatine387
 */

#include "Utils/platform.h"

#include <argon2.h>

#include "Common/constants.h"

int Argon2id(uint8_t* salt, const char* pw, size_t plen, uint8_t* key) {
  return argon2id_hash_raw(kTimeCost, kMemCost, kParellelism, pw, plen, salt, kSaltSize, key, kKeySize);
}