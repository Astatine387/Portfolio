/**
 * @file	vault_interface.h
 * @brief	Vault interface between GUI and core layers
 * @author	Astatine387
 */

#pragma once

#include <QString>
#include <QVector>

#include "core/vault.h"
#include "gui/entry_interface.h"
#include "utils/password.h"

class VaultInterface {
 public:
  /* ==================================================
   * Constructor and Destructor
   * ================================================== */

  /**
   * @brief	Constructor of VaultInterface class
   */
  VaultInterface();

  /**
   * @brief	Destructor of VaultInterface class
   */
  ~VaultInterface() = default;

  /* ==================================================
   * Vault file functions
   * ================================================== */

  /**
   * @brief		Create an empty new vault
   * @param		path    Vault file path
   * @param		pw      Master password
   * @return	kSuccess on success, kFailure on failure
   */
  Result NewVault(const QString& path, const Password& pw);

  /**
   * @brief		Open a vault and read its data
   * @param		path	Vault file path
   * @param		pw      Master password
   * @return	kSuccess on success, kFailure on failure
   */
  Result OpenVault(const QString& path, const Password& pw);

  /**
   * @brief		Save the current vault
   * @return	kSuccess on success, kFailure on failure
   */
  Result SaveVault();

  /**
   * @brief	Close the vault and wipe all data
   */
  void CloseVault();

  /* ==================================================
   * Vault password functions
   * ================================================== */

  /**
   * @brief		Verify the master password
   * @param		pw  Password to verify
   * @return	true if password is correct
   */
  [[nodiscard]] bool VerifyPW(const Password& pw) const;

  /**
   * @brief		Change the master password and re-encrypt vault
   * @param		pw      New password
   * @return	kSuccess on success, kFailure on save failure
   */
  Result ChangePW(const Password& pw);

  /* ==================================================
   * Entry CRUD functions
   * ================================================== */

  /**
   * @brief		Create a new entry
   * @param		site	Site name of the new entry
   * @param		acc		Account of the new entry
   * @param		pw		Password of the new entry
   * @return	kSuccess on success, kFailure on failure
   */
  Result CreateEntry(const QString& site, const QString& acc, const Password& pw);

  /**
   * @brief     Update an entry
   * @param     old_site    Site name of the target entry
   * @param     old_acc		Account of the target entry
   * @param     new_site    New site name
   * @param     new_acc		New account
   * @param     new_pw		New password
   * @return	kSuccess on success, kNotFound if original entry is missing,
   *          kDuplicate if the new site/account collides with another entry
   */
  UpdateResult UpdateEntry(const QString& old_site, const QString& old_acc, const QString& new_site,
                           const QString& new_acc, const Password& new_pw);

  /**
   * @brief     Delete an entry
   * @param     site	Site name of the target entry
   * @param     acc		Account of the target entry
   * @return    kSuccess on success, kFailure on failure
   */
  Result DeleteEntry(const QString& site, const QString& acc);

  /**
   * @brief	Get a reference to the entry set
   * @return	Reference to the entry set
   */
  [[nodiscard]] QVector<EntryView> GetEntries() const;

  /**
   * @brief     Get the password of an entry
   * @param     site    Site name
   * @param     acc     Account
   * @param     pw      Password of the found entry
   * @return    true if entry found, false otherwise
   */
  bool GetPW(const QString& site, const QString& acc, Password& pw) const;

  /**
   * @brief     Get the last error message
   * @return	Last error message
   */
  [[nodiscard]] QString GetLastError() const;

 private:
  std::unique_ptr<Vault> vault_;
  QString vault_path_;
  QString last_error_;
};