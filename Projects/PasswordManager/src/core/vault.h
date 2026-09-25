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
 * @enum    UpdateResult
 * @brief   Outcome of an entry update operation
 */
enum class UpdateResult : std::uint8_t {
  kSuccess,    // Success
  kNotFound,   // Original entry is missing
  kDuplicate,  // Site or account collides with another entry
  kError,      // New fields are out of range, or the new image could not be built
};

/**
 * @class   Vault
 * @brief   Manages password vaults
 */
class Vault {
 public:
  /**
   * @enum    ImageOrigin
   * @brief   Where an image handed to VerifyImage came from
   *
   * kFile is an image parsed out of a vault file, which is to say bytes this process did not write and has no reason
   * to trust. kSession is one this process built from its own entry set, where a refusal means a rebuild went wrong
   * rather than a file being malformed. The two differ in nothing VerifyImage checks; they differ in what a failure
   * is about, and the reported message says which.
   */
  enum class ImageOrigin : std::uint8_t {
    kFile,     // Parsed out of a vault file
    kSession,  // Built by this process from the entry set
  };

  /**
   * @enum    PublishMode
   * @brief   What the commit point of SaveVaultWith may do to the path it publishes onto
   *
   * Creating and saving write the same bytes and differ in their precondition. A save may replace, because the file
   * at the path is the vault this session already owns; a create must succeed only if the name is free. The second of
   * those cannot be settled by testing the path first, since the test would be separated from the publish by the
   * seconds of Argon2id that run in between, and a sync client or a second instance can take the name inside that
   * window. So the mode is carried down to the rename and the rename decides it, in one step that cannot be
   * interleaved with.
   */
  enum class PublishMode : std::uint8_t {
    kReplace,     // Save: the file at the path is this session's own vault
    kCreateOnly,  // Create: the name must be free, decided atomically by the rename
  };

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
   * @brief   Create an empty new vault
   * @param   path  Vault file path
   * @param   pw  Master password (used to derive the session key)
   * @return  kSuccess on success, kFailure on failure
   *
   * Creates rather than replaces. A path that is already taken is refused and whatever holds it is left as it was,
   * whether or not that file is a vault.
   */
  Result NewVault(const std::string& path, const Password& pw);

  /**
   * @brief   Open a vault and read its data
   * @param   path  Vault file path
   * @param   pw  Master password (used to derive the session key)
   * @return  kSuccess on success, kFailure on failure
   */
  Result OpenVault(const std::string& path, const Password& pw);

  /**
   * @brief   Save the current vault, reusing the session key with a fresh IV
   * @param   path  Vault file path
   * @return  kSuccess on success, kFailure on failure
   */
  Result SaveVault(const std::string& path);

  /**
   * @brief	Close the vault and wipe all session state
   */
  void CloseVault();

  /**
   * @brief   Report whether the session holds changes that no file has received yet
   * @return  true if the image changed after this session last published a vault file
   *
   * Set by CommitImage and cleared once SaveVaultWith has renamed a file into place, whichever key that file was
   * written under, so a password change that saves the image counts as a save. Opening, creating and closing all
   * start from a clean session. Whoever is about to drop the session asks this first, since the image is the only
   * copy of what was changed.
   */
  [[nodiscard]] bool IsDirty() const { return dirty_; }

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
   * @param		pw    New password
   * @param		path  Vault file path
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
   *
   * The fields are checked against what the on-disk format accepts before anything is built, so a vault never holds
   * an entry it could not read back. GetLastError names the field that was refused.
   */
  Result CreateEntry(const std::string& site, const std::string& acc, const Password& pw);

  /**
   * @brief   Update an entry
   * @param   old_site  Site name of the target entry
   * @param   old_acc   Account of the target entry
   * @param   new_site  New site name
   * @param   new_acc   New account
   * @param   new_pw    New password
   * @return  See UpdateResult
   *
   * The new fields are checked as CreateEntry's are, and a field out of range gives kError with the reason in
   * GetLastError.
   */
  UpdateResult UpdateEntry(const std::string& old_site, const std::string& old_acc, const std::string& new_site,
                           const std::string& new_acc, const Password& new_pw);

  /**
   * @brief   Delete an entry
   * @param   site  Site name of the target entry
   * @param   acc   Account of the target entry
   * @return  kSuccess on success, kFailure on failure
   */
  Result DeleteEntry(const std::string& site, const std::string& acc);

  /**
   * @brief   Get a reference to the entry set
   * @return  Reference to the entry set
   */
  [[nodiscard]] const std::set<Entry, EntryCmp>& GetEntries() const;

  /**
   * @brief   Copy an entry's password out of the locked image
   * @param   site  Site name
   * @param   acc   Account
   * @param   dst   Destination password
   * @return  true if the entry was found and copied
   */
  [[nodiscard]] bool GetEntryPW(const std::string& site, const std::string& acc, Password& dst);

  /**
   * @brief   Get the number of entries
   * @return  Number of entries
   */
  [[nodiscard]] int GetEntryCount() const;

  /* ==================================================
   * Callback functions
   * ================================================== */

  /**
   * @brief   Callback function for error reporting
   * @param   msg   Error message string
   */
  using ErrorCallback = std::function<void(const char* msg)>;

  /**
   * @brief   Set error callback function
   * @param   ecb   Error callback function
   */
  void SetErrorCallback(ErrorCallback ecb) { ecb_ = std::move(ecb); }

  /**
   * @brief   Get the last error message
   * @return  Last error message
   */
  [[nodiscard]] const std::string& GetLastError() const;

  /**
   * @brief   Get the warning left by the last successful operation
   * @return  Warning message, empty when the operation had nothing to warn about
   *
   * A warning accompanies kSuccess. It names something the operation completed without, rather than something it
   * failed to do: a vault that was published while its directory entry could not be flushed is saved, and saying so
   * is the only way a caller can both trust the file and know what was not confirmed about it.
   */
  [[nodiscard]] const std::string& GetLastWarning() const { return last_warning_; }

 private:
  AesGcm aes_;
  std::optional<SecureKey> key_;           // Session key derived at open/change
  std::array<uint8_t, kSaltSize> salt_{};  // Session salt (also written to the file header)
  KdfParams kdf_;                          // Argon2id parameters of the open vault (also written to the header)
  SecureBuffer img_;                       // Decrypted vault image (entry passwords live here)
  bool dirty_ = false;                     // Image changed after this session last published a file
  std::set<Entry, EntryCmp> entry_set_;
  std::string last_error_;
  std::string last_warning_;

  ErrorCallback ecb_ = nullptr;

  std::vector<uint8_t> src_buff_;
  std::vector<uint8_t> dst_buff_;
  FILE* file_ = nullptr;
  int64_t src_size_ = 0;
  int64_t dst_size_ = 0;

  /* ==================================================
   * Helper functions
   * ================================================== */

  /**
   * @brief	Wipe the transient file buffers
   */
  void Clear();

  /**
   * @brief	Wipe all session state (key, salt, image, entries, unsaved-change flag)
   */
  void Reset();

  /**
   * @brief   Encrypt the current image with a given key, then write atomically
   * @param   path  Vault file path
   * @param   key   Key to encrypt with
   * @param   mode  Whether the publish may replace what is at @p path, or must find the name free
   * @return  kSuccess on success, kFailure on failure
   *
   * The header is built from @p key alone. Passed beside it as separate arguments, the salt and the parameters could
   * record a derivation the key had not come from; taking them from the key leaves no argument to get wrong.
   *
   * @p mode reaches the commit point and nothing before it. Everything up to the rename writes a temporary file of
   * its own, which a create and a save do identically; the rename is the only step that touches @p path, and so the
   * only one that can tell the two apart.
   */
  Result SaveVaultWith(const std::string& path, const SecureKey& key, PublishMode mode);

  /**
   * @brief   Serialize every entry except one into a candidate image and record their offsets in it
   * @param   dst           Destination image buffer
   * @param   cur           Current write cursor
   * @param   out_entries   Candidate entry set the rewritten entries are inserted into
   * @param   skip          Entry to skip (entry_set_.end() to skip none)
   * @return  New write cursor, or std::nullopt when a span check fails
   *
   * Reads from @p entry_set_ and the current image, and writes only to @p dst and @p out_entries. The offsets it
   * computes describe @p dst, which is not the installed image yet, so writing them onto the live entries would
   * leave them pointing into a buffer that does not exist until CommitImage accepts this one.
   */
  std::optional<size_t> SerializeVault(SecureBuffer& dst, size_t cur, std::set<Entry, EntryCmp>& out_entries,
                                       const std::set<Entry, EntryCmp>::const_iterator& skip);

  /**
   * @brief   Verify an image against the entry set that describes it
   * @param   img       Image to check
   * @param   entries   Entry set the image is expected to match
   * @param   origin    Where @p img came from, which selects how a failure is reported
   * @return  kSuccess when intact, kFailure on any mismatch
   *
   * Four things are checked, all of them about the image and the entry set still describing each other: the entry
   * count at the front of the image equals the size of @p entries, every entry re-parses out of the image, each
   * re-parsed entry is present in @p entries with the same password offset and length, and the last entry ends
   * exactly at the end of the image. An image too short to hold the count field fails the first of these. Nothing
   * about the allocation the image lives in is inspected here.
   *
   * This is the one place the format states what a complete image is, and all three callers pass through it:
   * OpenVault checks what it parsed out of a file before installing it, CommitImage checks a rebuild before it
   * becomes the session, and SaveVaultWith checks the installed pair before it is written. Stated once and checked
   * on every path, a vault that would fail one of them cannot be opened, built or saved rather than being caught by
   * whichever path happened to ask.
   *
   * Takes the pair as arguments rather than reading the members, so a candidate can be checked before it is
   * installed. Not const because ReportError is not.
   */
  Result VerifyImage(const SecureBuffer& img, const std::set<Entry, EntryCmp>& entries, ImageOrigin origin);

  /**
   * @brief   Install a verified image and entry set as the session state
   * @param   img       Candidate image
   * @param   entries   Candidate entry set
   * @return  kSuccess when the pair was verified and installed, kFailure when nothing was touched
   *
   * The one place img_ and entry_set_ are ever written after a vault is open. A caller builds both aside, hands them
   * over together, and on failure both die with the call while the session keeps the image it already had.
   *
   * Being the one place, it is also where the session is marked dirty, so an operation added later cannot change the
   * image without IsDirty noticing.
   */
  Result CommitImage(SecureBuffer&& img, std::set<Entry, EntryCmp>&& entries);

  /* ==================================================
   * Callback helper functions
   * ================================================== */

  /**
   * @brief   Report error via callback
   * @param   msg   Error message string
   */
  void ReportError(const char* msg);
};
