/**
 * @file	clipboard.h
 * @brief	Declaration of clipboard helper functions
 * @author	Astatine387
 */

#pragma once

#include "utils/password.h"

/**
 * @namespace	clipboard
 * @brief		Clipboard helpers that keep a copied password out of OS history
 */
namespace clipboard {

/**
 * @brief	Copy a password to the system clipboard, excluded from OS history and cloud sync
 * @param	pw	Password to place on the clipboard
 */
void SetSecret(const Password& pw);

/**
 * @brief	Clear the clipboard only if this application still owns it
 * @return	true if the clipboard was owned and cleared
 */
bool ClearIfOwned();

}  // namespace clipboard
