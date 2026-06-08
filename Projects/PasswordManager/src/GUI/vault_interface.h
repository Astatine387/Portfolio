/**
 * @file	vault_interface.h
 * @brief	Vault interface for GUI layer
 * @author	Astatine387
 */

#pragma once

#include <QString>
#include <QVector>

#include "Core/vault.h"
#include "GUI/entry_interface.h"
#include "Utils/password.h"

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
   * @return	0 on success, 1 on failure
   */
  int NewVault(const QString& path);

  /**
   * @brief		Open a vault and read its data
   * @param		path	Vault file path
   * @return	0 on success, 1 on failure
   */
  int OpenVault(const QString& path);

  /**
   * @brief		Save the current vault
   * @return	0 on success, 1 on failure
   */
  int SaveVault();

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
   * @return	0 on success, 1 on save failure
   */
  int ChangePW(const Password& pw);

  /**
   * @brief     Set the master password of vault
   * @param     pw  Master password
   */
  void SetPW(const Password& pw);

  /* ==================================================
   * Entry CRUD functions
   * ================================================== */

  /**
   * @brief		Create a new entry
   * @param		site	Site name of the new entry
   * @param		acc		Account of the new entry
   * @param		pw		Password of the new entry
   * @return	0 on success, 1 on failure
   */
  int CreateEntry(const QString& site, const QString& acc, const Password& pw);

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
   * @return    0 on success, 1 on failure
   */
  int DeleteEntry(const QString& site, const QString& acc);

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