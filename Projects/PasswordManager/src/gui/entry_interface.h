/**
 * @file	entry_interface.h
 * @brief	Entry Interface between GUI and core layers
 * @author	Astatine387
 */

#pragma once

#include <QString>

#include "utils/password.h"

/**
 * @struct	EntryView
 * @brief	Entry interface for data read
 */
struct EntryView {
  QString site;
  QString acc;
};

/**
 * @struct	EntryInput
 * @brief	Entry interface for data input
 */
struct EntryInput {
  QString site;
  QString acc;
  Password pw;
};