/**
 * @file	platform.cpp
 * @brief	Implementation of common utility functions
 * @author	Astatine387
 */

#include "utils/platform.h"

#include "common/constants.h"

Result RandomRange(uint32_t* dst, uint32_t min, uint32_t max) {
  /* Reject an inverted range */

  if (min > max) {
    return Result::kFailure;
  }

  /* Reject the full range, whose size overflows uint32_t to zero */

  if (min == 0 && max == UINT32_MAX) {
    return Result::kFailure;
  }

  uint32_t range = max - min + 1;
  uint32_t limit = UINT32_MAX - UINT32_MAX % range;
  uint32_t tmp;

  do {
    if (Random(reinterpret_cast<uint8_t*>(&tmp), sizeof(uint32_t)) == Result::kFailure) {
      return Result::kFailure;  // LCOV_EXCL_LINE
    }
  } while (tmp >= limit);

  *dst = min + tmp % range;

  return Result::kSuccess;
}

Result Shuffle(uint8_t* arr, int size) {
  uint32_t idx;

  for (int i = 0; i < size; i++) {
    if (RandomRange(&idx, i, size - 1) == Result::kFailure) {
      return Result::kFailure;  // LCOV_EXCL_LINE
    }

    Swap(&arr[i], &arr[idx]);
  }

  return Result::kSuccess;
}

void Swap(uint8_t* a, uint8_t* b) {
  uint8_t tmp = *a;
  *a = *b;
  *b = tmp;
}