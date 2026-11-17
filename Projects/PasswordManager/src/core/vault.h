/**
 * @file    vault.h
 * @brief   Manages password vaults
 * @author  Astatine387
 */

#pragma once

#include <array>
#include <cstdint>
#include <functional>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <vector>

#include "common/constants.h"
#include "core/aes_gcm.h"
#include "core/entry.h"
#include "core/secure_buffer.h"
#include "core/secure_key.h"
#include "utils/password.h"

/**
 * @brief   Outcome of an entry update operation
 */
enum class UpdateResult : std::uint8_t {
  kSuccess,    // Success
  kNotFound,   // Original entry is missing
  kDuplicate,  // Site or account collides with another entry
  kError,      // New fields are out of range, or new image cannot be built
};

/**
 * @brief   Outcome of publishing the session onto a vault file
 */
enum class SaveResult : std::uint8_t {
  kSuccess,   // The session was published
  kConflict,  // The file changed on disk and nothing was written
  kError,     // Any other failure; nothing was published
};

/**
 * @brief   What will be done about a vault file that changed on disk
 */
enum class SaveMode : std::uint8_t {
  kRefuseChanged,          // Refuse to publish
  kOverwriteAcknowledged,  // Publish over the changed file
};

/**
 * @brief   Manages password vaults
 */
class Vault {
 public:
  /**
   * @brief   Where an image handed to VerifyImage came from
   */
  enum class ImageOrigin : std::uint8_t {
    kFile,     // Parsed out of a vault file
    kSession,  // Built by this process from the entry set
  };

  /**
   * @brief   Whether the publish may overwrite an existing file
   */
  enum class PublishMode : std::uint8_t {
    kReplace,     // Save: the file at the path is this session's own vault
    kCreateOnly,  // Create: the name must be free
  };

  /* ==================================================
   * Constructor and Destructor
   * ================================================== */

  /**
   * @brief   Default constructor of Vault class
   */
  Vault();

  /**
   * @brief   Default destructor of Vault class
   */
  ~Vault();

  /* ==================================================
   * Vault file functions
   * ================================================== */

  /**
   * @brief   Create an empty new vault
   * @param   path  Vault file path
   * @param   pw    Master password
   * @return  kSuccess on success, kFailure on failure
   */
  Result NewVault(const std::string& path, const Password& pw);

  /**
   * @brief   Open a vault and read its data
   * @param   path  Vault file path
   * @param   pw    Master password
   * @return  kSuccess on success, kFailure on failure
   */
  Result OpenVault(const std::string& path, const Password& pw);

  /**
   * @brief   Save the current vault, reusing the session key with a fresh IV
   * @param   path  Vault file path
   * @param   mode  What will be done about a vault file that changed on disk
   * @return  kSuccess on success, kConflict when the file changed on disk,
   * kError on other failures
   */
  SaveResult SaveVault(const std::string& path,
                       SaveMode mode = SaveMode::kRefuseChanged);

  /**
   * @brief   Close the vault and wipe all session state
   */
  void CloseVault();

  /**
   * @brief   Report whether the session holds unpublished changes
   * @return  true if the image changed after the last publish
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
   * @param		mode  What will be done about a vault file that changed on disk
   * @return	kSuccess on success, kConflict when the file changed on disk,
   * kError on other failures
   */
  SaveResult ChangePW(const Password& pw, const std::string& path,
                      SaveMode mode = SaveMode::kRefuseChanged);

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
  Result CreateEntry(const std::string& site, const std::string& acc,
                     const Password& pw);

  /**
   * @brief   Update an entry
   * @param   old_site  Site name of the target entry
   * @param   old_acc   Account of the target entry
   * @param   new_site  New site name
   * @param   new_acc   New account
   * @param   new_pw    New password
   * @return  See UpdateResult
   */
  UpdateResult UpdateEntry(const std::string& old_site,
                           const std::string& old_acc,
                           const std::string& new_site,
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
  [[nodiscard]] bool GetEntryPW(const std::string& site, const std::string& acc,
                                Password& dst);

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
   * @return  Warning message
   */
  [[nodiscard]] const std::string& GetLastWarning() const {
    return last_warning_;
  }

 private:
  /**
   * @brief   What a path held at the moment it was looked at
   */
  struct FileState {
    bool exists = false;
    bool has_iv = false;
    std::array<uint8_t, kIVSize> iv{};
    std::string file;

    bool operator==(const FileState& other) const = default;
  };

  /**
   * @brief   The vault version this session last read or published
   */
  struct FileMark {
    std::string path;
    std::string real_path;
    std::array<uint8_t, kIVSize> iv{};
  };

  /**
   * @brief   The changed file a refused save reported
   */
  struct Conflict {
    std::string path;
    FileState state;
  };

  AesGcm aes_;
  std::optional<SecureKey> key_;
  std::array<uint8_t, kSaltSize> salt_{};
  KdfParams kdf_;
  SecureBuffer img_;
  bool dirty_ = false;
  std::optional<FileMark> mark_;
  std::optional<Conflict> ack_;
  std::set<Entry, EntryCmp> entry_set_;
  std::string last_error_;
  std::string last_warning_;

  ErrorCallback ecb_ = nullptr;

  std::vector<uint8_t> src_buff_;  // Encrypted vault read from disk
  std::vector<uint8_t> dst_buff_;  // Encrypted vault to be written to disk
  FILE* file_ = nullptr;
  int64_t src_size_ = 0;
  int64_t dst_size_ = 0;

  /* ==================================================
   * Helper functions
   * ================================================== */

  /**
   * @brief   Wipe the transient file buffers
   */
  void Clear();

  /**
   * @brief   Wipe all session state
   */
  void Reset();

  /**
   * @brief   Encrypt the current image with a given key, then write atomically
   * @param   path  Vault file path
   * @param   key   Key to encrypt with
   * @param   mode  Whether the publish may overwrite an existing file
   * @param   save  What will be done about a vault file that changed on disk
   * @return  kSuccess on success, kConflict when the file changed on disk,
   * kError on other failures
   */
  SaveResult SaveVaultWith(const std::string& path, const SecureKey& key,
                           PublishMode mode, SaveMode save);

  /**
   * @brief   Read what a path holds
   * @param   path  Path to look at
   * @return  What was found there
   */
  static FileState ReadFileState(const std::string& path);

  /**
   * @brief   Record the vault version this session now holds
   * @param   path       Path the version was read from or written to
   * @param   real_path  File that path led to
   * @param   iv         IV of the bytes this session read or wrote
   */
  void RememberFile(const std::string& path, const std::string& real_path,
                    std::span<const uint8_t, kIVSize> iv);

  /**
   * @brief   Decide which file a replacing publish onto a path should act on
   * @param   path  Publish path
   * @return  The file to look at, write beside and rename onto
   */
  [[nodiscard]] std::string ReplaceTarget(const std::string& path) const;

  /**
   * @brief   Decide whether a publish onto a file may go ahead
   * @param   path  Publish path
   * @param   dst   Destination file
   * @param   mode  What will do about a vault file that changed on disk
   * @return  kSuccess on success, kConflict when the file changed on disk,
   * kError on other failures
   */
  SaveResult CheckTarget(const std::string& path, const std::string& dst,
                         SaveMode mode);

  /**
   * @brief   Serialize entries and record their offsets in it
   * @param   src   Source image buffer
   * @param   cur   Current write cursor
   * @param   dst   Destination entry set
   * @param   skip  Entry to skip
   * @return  New write cursor, or std::nullopt when a span check fails
   */
  std::optional<size_t> SerializeVault(
      SecureBuffer& src, size_t cur, std::set<Entry, EntryCmp>& dst,
      const std::set<Entry, EntryCmp>::const_iterator& skip);

  /**
   * @brief   Verify an image against the entry set that describes it
   * @param   img       Image to check
   * @param   entries   Entry set the image is expected to match
   * @param   origin    Where the image came from
   * @return  kSuccess when intact, kFailure on any mismatch
   */
  Result VerifyImage(const SecureBuffer& img,
                     const std::set<Entry, EntryCmp>& entries,
                     ImageOrigin origin);

  /**
   * @brief   Install a verified image and entry set as the session state
   * @param   img       Candidate image
   * @param   entries   Candidate entry set
   * @return  kSuccess when the pair was verified and installed, kFailure when
   * nothing was touched
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
