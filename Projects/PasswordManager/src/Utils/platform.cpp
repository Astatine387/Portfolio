/**
 * @file	platform.cpp
 * @brief	Implementation of common utility functions
 * @author	Astatine387
 */

#include "Utils/platform.h"

#include <argon2.h>

#include "Common/constants.h"

uint32_t RandomRange(uint32_t min, uint32_t max) {
  uint32_t range = max - min + 1, limit = UINT32_MAX - UINT32_MAX % range;
  uint32_t tmp;

  do {
    Random(reinterpret_cast<uint8_t*>(&tmp), sizeof(uint32_t));
  } while (tmp >= limit);

  return min + tmp % range;
}

int Argon2id(uint8_t* salt, const char* pw, size_t plen, uint8_t* key) {
  return argon2id_hash_raw(kTimeCost, kMemCost, GetProcNum(), pw, plen, salt, kSaltSize, key, kKeySize);
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