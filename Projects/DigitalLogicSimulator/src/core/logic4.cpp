/**
 * @file    logic4.cpp
 * @brief   Out-of-line definitions for the Logic4 value model
 * @author  Astatine387
 */

#include "core/logic4.h"

#include <ostream>

std::ostream& operator<<(std::ostream& os, Logic4 v) {
  return os << ToChar(v);
}