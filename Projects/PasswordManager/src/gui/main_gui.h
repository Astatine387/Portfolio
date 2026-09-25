/**
 * @file	main_gui.h
 * @brief	Main GUI class that controls entire workflow
 * @author	Astatine387
 */

#pragma once

#include <QStackedWidget>
#include <QString>
#include <QTimer>
#include <QVBoxLayout>
#include <QWidget>
#include <cstdint>
#include <functional>

#include "core/vault.h"
#include "gui/change_pw_gui.h"
#include "gui/entry_gui.h"
#include "gui/list_gui.h"
#include "gui/login_gui.h"
#include "gui/password_gui.h"
#include "gui/vault_interface.h"

/**
 * @class	MainGUI
 * @brief	Main GUI class that orchestrates entire workflow
 */
class MainGUI : public QWidget {
  Q_OBJECT

 public:
  /**
   * @brief	Constructor of MainGUI class
   * @param	parent	Parent widget
   */
  explicit MainGUI(QWidget* parent = nullptr);

  /**
   * @brief	Destructor of MainGUI class
   */
  ~MainGUI() override;

  /* ==================================================
   * Callback functions
   * ================================================== */

  /**
   * @brief	Callback function for error reporting
   * @param	err_msg	Error message string
   */
  using ErrorCallback = std::function<void(const char* err_msg)>;

  /**
   * @brief	Set error callback function
   * @param	ecb		Error callback function
   */
  void SetErrorCb(ErrorCallback ecb) { this->ecb_ = std::move(ecb); }

 private slots:
  /**
   * @brief	Switch to password input screen
   * @param	action	Vault action (kCreate or kOpen)
   * @param	path	Vault file path
   */
  void OnVaultSelected(VaultAction action, const QString& path);

  /**
   * @brief	Process vault login request
   * @param	req	Login input parameters
   */
  void OnLoginRequested(const LoginRequest& req);

  /**
   * @brief	Return to login screen
   */
  void OnBackToLogin();

  /**
   * @brief	Process entry add request
   */
  void OnAddRequested();

  /**
   * @brief	Process entry edit request
   * @param	site	Site of entry to be edited
   * @param	acc		Account of entry to be edited
   */
  void OnEditRequested(const QString& site, const QString& acc);

  /**
   * @brief	Process entry delete request
   * @param	site	Site of entry to be deleted
   * @param	acc		Account of entry to be deleted
   */
  void OnDeleteRequested(const QString& site, const QString& acc);

  /**
   * @brief	Process copy password request
   * @param	site	Site of entry to copy password from
   * @param	acc		Account of entry to copy password from
   */
  void OnCopyPWRequested(const QString& site, const QString& acc);

  /**
   * @brief	Process vault save request
   */
  void OnSaveRequested();

  /**
   * @brief	Process vault close request
   */
  void OnCloseRequested();

  /**
   * @brief	Process change master password request
   */
  void OnChangePWRequested();

 private:
  /**
   * @enum    SaveResult
   * @brief   What a publish routed through the conflict prompt ended up doing
   *
   * kCancelled is separated from kError because the two say opposite things to a user. An error is something that
   * went wrong and may be worth retrying; a cancellation is the answer they just gave, and the file is untouched
   * because they said so. Reporting the second as the first would read as a malfunction.
   */
  enum class SaveResult : std::uint8_t {
    kSaved,      // Published, with nothing else having touched the file
    kOverwrote,  // Published over changes another program had made, after the user acknowledged them
    kCancelled,  // The file had changed and the user chose not to overwrite it; nothing was written
    kError,      // The operation failed for another reason; GetLastError says which
  };

  ChangePWGUI* change_pw_gui_;
  EntryGUI* entry_gui_;
  ListGUI* list_gui_;
  LoginGUI* login_gui_;
  PasswordGUI* pw_gui_;
  QStackedWidget* stack_;
  QTimer* timer_ = nullptr;
  QVBoxLayout* vbox_;
  VaultInterface vault_;

  int countdown_ = 0;

  QString orig_site_;
  QString orig_acc_;

  ErrorCallback ecb_ = nullptr;

  /**
   * @brief	Confirm unsaved changes, then clean timer and clipboard when GUI is closed
   */
  void closeEvent(QCloseEvent* event) override;

  /**
   * @brief	Refresh list GUI
   */
  void RefreshList();

  /**
   * @brief	Ask what to do with unsaved changes before the open vault is dropped
   * @return	true if the caller may drop the vault (nothing unsaved, saved now, or discarded on purpose)
   *
   * Saving from the prompt and failing returns false and shows the reason, so the changes stay open to retry or to
   * discard knowingly.
   */
  [[nodiscard]] bool ConfirmDiscard();

  /**
   * @brief	Run a publish, asking before it overwrites a vault file that changed on disk
   * @param	op	The publish to run, called with the mode it is to run under
   * @return	What the publish ended up doing
   *
   * The one route to the disk for all three of the places that save, so none of them can overwrite another window's
   * work without asking, or report that refusal as an ordinary failure. @p op is a function rather than a flag
   * because the two operations behind it differ in more than a name: a password change needs a wait cursor around
   * itself and a save does not, and that belongs to the caller that knows which it is running.
   *
   * The retry is a loop rather than a single second attempt. The file can change again between the prompt and the
   * answer, and the core acknowledges only the version the user was shown, so that second change comes back as
   * another conflict and is asked about in its turn instead of being replaced unseen.
   */
  [[nodiscard]] SaveResult SaveWithConflictPrompt(const std::function<SaveResult(SaveMode)>& op);

  /**
   * @brief	Ask whether to overwrite a vault file that changed on disk
   * @return	true if the user chose to overwrite it
   *
   * Cancel is both the default and the escape button, so neither Enter nor Escape can overwrite. The destructive
   * answer is the one that has to be aimed at.
   */
  [[nodiscard]] bool ConfirmOverwrite();

  /**
   * @brief	End the clipboard countdown and take the copied password off the clipboard
   *
   * The two belong together: stopping the countdown on its own would leave the password on the clipboard with
   * nothing left to remove it. A clipboard this application no longer owns is left as it is, and calling this
   * with no countdown running does nothing, since the password has already gone or was never copied.
   */
  void StopClipboardCountdown();
};
