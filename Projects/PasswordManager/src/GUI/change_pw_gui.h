/**
 * @file	change_pw_gui.h
 * @brief	Master password change GUI
 * @author	Astatine387
 */

#pragma once

#include <QDialog>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QString>
#include <QVBoxLayout>
#include <QWidget>

#include "GUI/pw_line_edit.h"
#include "Utils/password.h"

/**
 * @class	ChangePWGUI
 * @brief	Dialog for changing the master password
 */
class ChangePWGUI : public QDialog {
  Q_OBJECT

 public:
  /**
   * @brief	Constructor of ChangePWGUI class
   * @param	parent	Parent widget
   */
  explicit ChangePWGUI(QWidget* parent = nullptr);

  /**
   * @brief		Get the change password input from the dialog
   * @cur_pw	Current password will be extracted here
   * @new_pw	New password will be extracted here
   */
  void GetInput(Password& cur_pw, Password& new_pw);

  /**
   * @brief	Reset all input fields
   */
  void Reset();

  /**
   * @brief	Display error message
   * @param	msg		Error message string
   */
  void SetErrMsg(const QString& msg);

  /* ==================================================
   * Callback functions
   * ================================================== */

  /**
   * @brief	Callback function for verifying current password
   * @param	curPW	Current password to verify
   * @return	true if password is correct
   */
  using VerifyCallback = std::function<bool(const Password& cur_pw)>;

  /**
   * @brief	Set verify callback function
   * @param	vcb		Verify callback function
   */
  void SetVerifyCb(VerifyCallback vcb);

 private slots:
  /**
   * @brief	Validate input and accept dialog
   */
  void OnOKClicked();

 private:
  PWLineEdit* cur_pwline_;
  PWLineEdit* new_pwline_;
  PWLineEdit* confirm_pwline_;
  QLabel* cur_label_;
  QLabel* new_label_;
  QLabel* confirm_label_;
  QLabel* err_msg_;
  QPushButton* ok_btn_;
  QPushButton* cancel_btn_;
  QHBoxLayout* btn_box_;
  QVBoxLayout* vbox_;

  VerifyCallback vcb_ = nullptr;
};