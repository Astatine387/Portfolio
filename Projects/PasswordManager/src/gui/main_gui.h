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
  bool is_edit_mode_ = false;

  ErrorCallback ecb_ = nullptr;

  /**
   * @brief	Clean timer and clipboard when GUI is closed
   */
  void closeEvent(QCloseEvent* event) override;

  /**
   * @brief	Refresh list GUI
   */
  void RefreshList();
};