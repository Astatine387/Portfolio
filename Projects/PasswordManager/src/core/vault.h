/**
 * @file	vault.h
 * @brief	Manages password vaults
 * @author	Astatine387
 */

#pragma once

#include <array>
#include <cstdint>
#include <functional>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "common/constants.h"
#include "core/aes_gcm.h"
#include "core/entry.h"
#include "core/secure_buffer.h"
#include "core/secure_key.h"
#include "utils/password.h"

/**
 * @enum	UpdateResult
 * @brief	Outcome of an entry update operation
 */
enum class UpdateResult : std::uint8_t {
  kSuccess,    // Success
  kNotFound,   // Original entry is missing
  kDuplicate,  // Site or account collides with another entry
  kError,      // Secure memory could not be allocated
};

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
   * @param   pw      Master password (used to derive the session key)
   * @return  kSuccess on success, kFailure on failure
   */
  Result NewVault(const std::string& path, const Password& pw);

  /**
   * @brief	Open a vault and read its data
   * @param   path    Vault file path
   * @param   pw      Master password (used to derive the session key)
   * @return  kSuccess on success, kFailure on failure
   */
  Result OpenVault(const std::string& path, const Password& pw);

  /**
   * @brief	Save the current vault, reusing the session key with a fresh IV
   * @param   path    Vault file path
   * @return	kSuccess on success, kFailure on failure
   */
  Result SaveVault(const std::string& path);

  /**
   * @brief	Close the vault and wipe all session state
   */
  void CloseVault();

  /* ==================================================
   * Vault password functions
   * ================================================== */

  /**
   * @brief		Verify a password against the session key
   * @param		pw  Password to verify
   * @return	true if the password derives the current session key
   */
  [[nodiscard]] bool VerifyPW(const Password& pw) const;

  /**
   * @brief		Change the master password and re-encrypt the vault
   * @param		pw      New password
   * @param		path	Vault file path
   * @return	kSuccess on success, kFailure on save failure
   */
  Result ChangePW(const Password& pw, const std::string& path);

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
  Result CreateEntry(const std::string& site, const std::string& acc, const Password& pw);

  /**
   * @brief     Update an entry
   * @param     old_site    Site name of the target entry
   * @param     old_acc		Account of the target entry
   * @param     new_site    New site name
   * @param     new_acc		New account
   * @param     new_pw		New password
   * @return	See UpdateResult
   */
  UpdateResult UpdateEntry(const std::string& old_site, const std::string& old_acc, const std::string& new_site,
                           const std::string& new_acc, const Password& new_pw);

  /**
   * @brief     Delete an entry
   * @param     site	Site name of the target entry
   * @param     acc		Account of the target entry
   * @return    kSuccess on success, kFailure on failure
   */
  Result DeleteEntry(const std::string& site, const std::string& acc);

  /**
   * @brief	Get a reference to the entry set
   * @return	Reference to the entry set
   */
  [[nodiscard]] const std::set<Entry, EntryCmp>& GetEntries() const;

  /**
   * @brief     Copy an entry's password out of the locked image
   * @param     site    Site name
   * @param     acc     Account
   * @param     dst     Destination password
   * @return    true if the entry was found and copied
   */
  [[nodiscard]] bool GetEntryPW(const std::string& site, const std::string& acc, Password& dst) const;

  /**
   * @brief     Get the number of entries
   * @return	Number of entries
   */
  [[nodiscard]] int GetEntryCount() const;

  /* ==================================================
   * Callback functions
   * ================================================== */

  /**
   * @brief     Callback function for error reporting
   * @param     errMsg	Error message string
   */
  using ErrorCallback = std::function<void(const char* msg)>;

  /**
   * @brief     Set error callback function
   * @param     ecb		Error callback function
   */
  void SetErrorCallback(ErrorCallback ecb) { ecb_ = std::move(ecb); };

  /**
   * @brief     Get the last error message
   * @return	Last error message
   */
  [[nodiscard]] const std::string& GetLastError() const;

 private:
  AesGcm aes_;
  std::optional<SecureKey> key_;           // Session key derived at open/change
  std::array<uint8_t, kSaltSize> salt_{};  // Session salt (also written to the file header)
  KdfParams kdf_;                          // Argon2id parameters for this session
  SecureBuffer img_;                       // Decrypted vault image (entry passwords live here)
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

  /**
   * @brief	Wipe the transient file buffers
   */
  void Clear();

  /**
   * @brief	Wipe all session state (key, salt, image, entries)
   */
  void Reset();

  /**
   * @brief     Encrypt the current image with a given key and salt, then write atomically
   * @param     path	Vault file path
   * @param     key		Key to encrypt with
   * @param     salt	Salt to write to the header
   * @return	kSuccess on success, kFailure on failure
   */
  Result SaveVaultWith(const std::string& path, const SecureKey& key, std::span<const uint8_t, kSaltSize> salt);

  /**
   * @brief     Serialize every entry except one into a new image and refresh offsets
   * @param     dst		Destination image buffer
   * @param     cur		Current write cursor
   * @param     skip	Entry to skip (entry_set_.end() to skip none)
   * @return	New write cursor
   */
  size_t SerializeVault(uint8_t* dst, size_t cur, const std::set<Entry, EntryCmp>::const_iterator& skip);

  /* ==================================================
   * Callback helper functions
   * ================================================== */

  /**
   * @brief     Report error via callback
   * @param     msg		Error message string
   */
  void ReportError(const char* msg);
};
