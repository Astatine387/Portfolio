/**
 * @file    clipboard.h
 * @brief   Declaration of clipboard helper functions
 * @author  Astatine387
 */

#pragma once

#include "utils/password.h"

/**
 * @brief   Clipboard helpers that keep a copied password out of OS history
 */
namespace clipboard {

/**
 * @brief   Copy a password to the system clipboard
 * @param   pw  Password to copy
 */
void SetSecret(const Password& pw);

/**
 * @brief   Clear the clipboard only if this application still owns it
 * @return  true if the clipboard was owned and cleared
 */
bool ClearIfOwned();

}  // namespace clipboard
