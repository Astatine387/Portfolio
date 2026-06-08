/**
 * @file	change_pw_gui.cpp
 * @brief	Implementation of ChangePWGUI class
 * @author	Astatine387
 */

#include "GUI/change_pw_gui.h"

ChangePWGUI::ChangePWGUI(QWidget* parent) : QDialog(parent) {
  /* Create layouts and components */

  cur_pwline_ = new PWLineEdit;
  new_pwline_ = new PWLineEdit;
  confirm_pwline_ = new PWLineEdit;
  cur_label_ = new QLabel("Current Password:");
  new_label_ = new QLabel("New Password:");
  confirm_label_ = new QLabel("Confirm New Password:");
  err_msg_ = new QLabel;
  ok_btn_ = new QPushButton("Ok");
  cancel_btn_ = new QPushButton("Cancel");
  btn_box_ = new QHBoxLayout;
  vbox_ = new QVBoxLayout;

  /* Configure error message */

  err_msg_->setStyleSheet("color: red;");

  /* Configure button layout */

  btn_box_->addStretch();
  btn_box_->addWidget(ok_btn_);
  btn_box_->addWidget(cancel_btn_);

  /* Configure main layout */

  vbox_->addWidget(cur_label_);
  vbox_->addWidget(cur_pwline_);
  vbox_->addWidget(new_label_);
  vbox_->addWidget(new_pwline_);
  vbox_->addWidget(confirm_label_);
  vbox_->addWidget(confirm_pwline_);
  vbox_->addWidget(err_msg_);
  vbox_->addLayout(btn_box_);
  vbox_->setSpacing(10);
  vbox_->setContentsMargins(20, 20, 20, 20);

  setLayout(vbox_);
  setWindowTitle("Change Master Password");
  setMinimumWidth(400);

  /* Connect functions to buttons */

  connect(ok_btn_, &QPushButton::clicked, this, &ChangePWGUI::OnOKClicked);
  connect(cancel_btn_, &QPushButton::clicked, this, &QDialog::reject);
}

void ChangePWGUI::GetInput(Password& cur_pw, Password& new_pw) {
  cur_pwline_->Extract(cur_pw);
  new_pwline_->Extract(new_pw);
}

void ChangePWGUI::Reset() {
  cur_pwline_->Clear();
  new_pwline_->Clear();
  confirm_pwline_->Clear();
  err_msg_->clear();
}

void ChangePWGUI::SetErrMsg(const QString& msg) {
  err_msg_->setText(msg);
}

void ChangePWGUI::SetVerifyCb(VerifyCallback vcb) {
  this->vcb_ = std::move(vcb);
}

void ChangePWGUI::OnOKClicked() {
  err_msg_->clear();

  /* Extract passwords for validation */

  Password cur_pw, new_pw, confirm_pw;

  cur_pwline_->Extract(cur_pw);

  if (new_pwline_->Extract(new_pw) == Result::kFailure) {
    err_msg_->setText("Password exceeds maximum length (256 characters)");
    return;
  }

  if (confirm_pwline_->Extract(confirm_pw) == Result::kFailure) {
    err_msg_->setText("Password exceeds maximum length (256 characters)");
    return;
  }

  /* Validate all fields are filled */

  if (cur_pw.IsEmpty()) {
    err_msg_->setText("Current password is not input");
    return;
  }

  if (new_pw.IsEmpty()) {
    err_msg_->setText("New password is not input");
    return;
  }

  if (confirm_pw.IsEmpty()) {
    err_msg_->setText("Confirm password is not input");
    return;
  }

  /* Validate new password matches confirmation */

  if (new_pw.GetSize() != confirm_pw.GetSize() || !new_pw.Equal(confirm_pw)) {
    err_msg_->setText("New and confirm password do not match");
    return;
  }

  /* Validate new password differs from current */

  if (new_pw.GetSize() == cur_pw.GetSize() && new_pw.Equal(cur_pw)) {
    err_msg_->setText("Old and new password are the same");
    return;
  }

  /* Verify current password via callback */

  if (vcb_ && !vcb_(cur_pw)) {
    err_msg_->setText("Current password is incorrect");
    cur_pwline_->Clear();
    new_pwline_->Clear();
    confirm_pwline_->Clear();
    return;
  }

  /* Restore passwords for getInput() */

  cur_pwline_->SetPassword(cur_pw);
  new_pwline_->SetPassword(new_pw);

  accept();
}