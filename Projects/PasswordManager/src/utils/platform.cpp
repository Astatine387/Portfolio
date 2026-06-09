/**
 * @file	platform.cpp
 * @brief	Implementation of common utility functions
 * @author	Astatine387
 */

#include "utils/platform.h"

#include <argon2.h>

#include "common/constants.h"

uint32_t RandomRange(uint32_t min, uint32_t max) {
  uint32_t range = max - min + 1, limit = UINT32_MAX - UINT32_MAX % range;
  uint32_t tmp;

  do {
    Random(reinterpret_cast<uint8_t*>(&tmp), sizeof(uint32_t));
  } while (tmp >= limit);

  return min + tmp % range;
}

Result Argon2id(uint8_t* salt, const char* pw, size_t plen, uint8_t* key) {
  if (argon2id_hash_raw(kTimeCost, kMemCost, kParallelism, pw, plen, salt, kSaltSize, key, kKeySize) != ARGON2_OK) {
    return Result::kFailure;  // LCOV_EXCL_LINE
  }

  return Result::kSuccess;
}

void Shuffle(uint8_t* arr, int size) {
  for (int i = 0; i < size; i++) {
    Swap(&arr[i], &arr[RandomRange(i, size - 1)]);
  }
}

void Swap(uint8_t* a, uint8_t* b) {
  uint8_t tmp = *a;
  *a = *b;
  *b = tmp;
}