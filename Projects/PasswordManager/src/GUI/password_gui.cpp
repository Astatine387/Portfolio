/**
 * @file	password_gui.cpp
 * @brief	Implementation of PasswordGUI class
 * @author	Astatine387
 */

#include "GUI/password_gui.h"

PasswordGUI::PasswordGUI(QWidget* parent) : QWidget(parent) {
  /* Create layouts and components */

  pw_line_ = new PWLineEdit;
  path_label_ = new QLabel;
  err_msg_ = new QLabel;
  back_btn_ = new QPushButton("Back");
  confirm_btn_ = new QPushButton("Confirm");
  btn_box_ = new QHBoxLayout;
  vbox_ = new QVBoxLayout;

  err_msg_->setContentsMargins(5, 0, 0, 0);

  /* Put buttons and error message in the same line */

  btn_box_->addWidget(confirm_btn_);
  btn_box_->addWidget(back_btn_);
  btn_box_->addStretch();

  btn_box_->setSpacing(10);
  btn_box_->setContentsMargins(0, 0, 0, 0);

  /* Configure main layout */

  vbox_->addStretch();
  vbox_->addWidget(pw_line_);
  vbox_->addLayout(btn_box_);
  vbox_->addWidget(err_msg_);
  vbox_->addStretch();

  vbox_->setSpacing(15);
  vbox_->setContentsMargins(10, 10, 10, 10);

  setLayout(vbox_);

  /* Connect functions to buttons */

  connect(confirm_btn_, &QPushButton::clicked, this,
          &PasswordGUI::OnConfirmClicked);
  connect(back_btn_, &QPushButton::clicked, this, &PasswordGUI::BackRequested);
}

void PasswordGUI::SetVaultInfo(VaultAction action, const QString& path) {
  action_ = action;
  path_ = path;

  QString mode_str = action == VaultAction::kCreate ? "Create" : "Open";

  path_label_->setText(mode_str + ": " + path);

  pw_line_->Clear();
  err_msg_->clear();
}

void PasswordGUI::SetErrMsg(const QString& msg) {
  err_msg_->setText(msg);
}

void PasswordGUI::OnConfirmClicked() {
  err_msg_->clear();

  /* Check password is input */

  LoginRequest req;

  if (pw_line_->Extract(req.pw)) {
    err_msg_->setText("Password exceeds maximum length (256 characters)");
    return;
  }

  if (req.pw.IsEmpty()) {
    err_msg_->setText("Password is not input");
    return;
  }

  /* Emit login request */

  req.action = action_;
  req.path = path_;

  emit LoginRequested(req);
}