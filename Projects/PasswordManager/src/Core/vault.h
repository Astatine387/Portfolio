/**
 * @file	vault.h
 * @brief	Manages password vaults
 * @author	Astatine387
 */

#pragma once

#include <functional>
#include <set>
#include <string>
#include <vector>

#include "Common/constants.h"
#include "Core/aes_gcm.h"
#include "Core/entry.h"

/**
 * @class	Vault
 * @brief	Manages password vaults
 */
class Vault {
 public:
  /* ==================================================
   * Constructor and Destructor
   * ================================================== */

  /**
   * @brief	Default constructor of Vault class
   */
  Vault();

  /**
   * @brief	Default destructor of Vault class
   */
  ~Vault();

  /* ==================================================
   * Vault file functions
   * ================================================== */

  /**
   * @brief	Create an empty new vault
   * @param   path    Vault file path
   * @return  0 on success, 1 on failure
   */
  int NewVault(const std::string& path);

  /**
   * @brief	Open a vault and read its data
   * @param   path    Vault file path
   * @return  0 on success, 1 on failure
   */
  int OpenVault(const std::string& path);

  /**
   * @brief	Save the current vault
   * @param   path    Vault file path
   * @return	0 on success, 1 on failure
   */
  int SaveVault(const std::string& path);

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
  bool VerifyPW(const Password& pw) const;

  /**
   * @brief		Change the master password and re-encrypt vault
   * @param		pw      New password
   * @param		path	Vault file path
   * @return	0 on success, 1 on save failure
   */
  int ChangePW(const Password& pw, const std::string& path);

  /**
   * @brief     Set the master password of vault
   * @param     pw	Master password
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
  int CreateEntry(const std::string& site, const std::string& acc, const Password& pw);

  /**
   * @brief     Update an entry
   * @param     old_site    Site name of the target entry
   * @param     old_acc		Account of the target entry
   * @param     new_site    New site name
   * @param     new_acc		New account
   * @param     new_pw		New password
   * @return	0 on success, 1 on failure
   */
  int UpdateEntry(const std::string& old_site, const std::string& old_acc, const std::string& new_site,
                  const std::string& new_acc, const Password& new_pw);

  /**
   * @brief     Delete an entry
   * @param     site	Site name of the target entry
   * @param     acc		Account of the target entry
   * @return    0 on success, 1 on failure
   */
  int DeleteEntry(const std::string& site, const std::string& acc);

  /**
   * @brief	Get a reference to the entry set
   * @return	Reference to the entry set
   */
  const std::set<Entry, EntryCmp>& GetEntries() const;

  /**
   * @brief	Get the number of entries
   * @return	Number of entries
   */
  int GetEntryCount() const;

  /* ==================================================
   * Callback functions
   * ================================================== */

  /**
   * @brief	Callback function for error reporting
   * @param	errMsg	Error message string
   */
  using ErrorCallback = std::function<void(const char* msg)>;

  /**
   * @brief	Set error callback function
   * @param	ecb		Error callback function
   */
  void SetErrorCallback(ErrorCallback ecb) { ecb_ = ecb; };

  /**
   * @brief     Get the last error message
   * @return	Last error message
   */
  const std::string& GetLastError() const;

 private:
  AesGcm aes_;
  Password pw_;
  std::set<Entry, EntryCmp> entry_set_;
  std::string last_error_;

  ErrorCallback ecb_ = nullptr;

  std::vector<uint8_t> src_buff_;
  std::vector<uint8_t> dst_buff_;
  FILE* file_ = nullptr;
  int64_t src_size_ = 0;
  int64_t dst_size_ = 0;
  uint32_t magic_num_ = kMagicNum;

  /* ==================================================
   * Helper functions
   * ================================================== */

  void Clear();

  /* ==================================================
   * Callback helper functions
   * ================================================== */

  /**
   * @brief	Report error via callback
   * @param	msg		Error message string
   */
  void ReportError(const char* msg);
};