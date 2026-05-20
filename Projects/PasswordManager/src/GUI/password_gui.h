/**
 * @file	PasswordGUI.h
 * @brief	Password input window for vault authentication
 * @author	Astatine387
 */

#pragma once

#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QString>
#include <QVBoxLayout>
#include <QWidget>

#include "Common/constants.h"
#include "GUI/pw_line_edit.h"
#include "Utils/password.h"

/**
 * @struct	LoginInput
 * @brief	Container for login input parameters
 */
struct LoginRequest {
  VaultAction action;
  QString path;
  Password pw;
};

/**
 * @class	PasswordGUI
 * @brief	Password input window for vault authentication
 */
class PasswordGUI : public QWidget {
  Q_OBJECT

 public:
  /**
   * @brief	Constructor of PasswordGUI class
   * @param	parent	Parent widget
   */
  explicit PasswordGUI(QWidget* parent = nullptr);

  /**
   * @brief	Set vault mode and path from LoginGUI
   * @param	mode	0 for new, 1 for open
   * @param	path	Vault file path
   */
  void SetVaultInfo(VaultAction action, const QString& path);

  /**
   * @brief	Display error message
   * @param	msg		Error message string
   */
  void SetErrMsg(const QString& msg);

 signals:
  /**
   * @brief	Signal when login is confirmed
   * @param	input	Login input parameters
   */
  void LoginRequested(const LoginRequest& req);

  /**
   * @brief	Signal when back button is clicked
   */
  void BackRequested();

 private slots:
  /**
   * @brief	Validate input and emit login request
   */
  void OnConfirmClicked();

 private:
  PWLineEdit* pw_line_;
  QLabel* path_label_;
  QLabel* err_msg_;
  QPushButton* back_btn_;
  QPushButton* confirm_btn_;
  QString path_;
  QHBoxLayout* btn_box_;
  QVBoxLayout* vbox_;

  VaultAction action_ = VaultAction::kCreate;
};