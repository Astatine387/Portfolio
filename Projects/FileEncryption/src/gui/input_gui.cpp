/**
 * @file	input_gui.cpp
 * @brief	Implementation of InputGUI class
 * @author	Astatine387
 */

#include "gui/input_gui.h"

InputGUI::InputGUI(QWidget* parent) : QWidget(parent) {
  /* Create layouts and components */

  mode_btn_ = new ModeButton;
  src_line_ = new QLineEdit;
  dst_line_ = new QLineEdit;
  pw_line_ = new PWLineEdit;
  start_btn_ = new QPushButton("Start");
  err_msg_ = new QLabel;
  hbox_ = new QHBoxLayout;
  vbox_ = new QVBoxLayout;

  /* Set placeholder text that indicates each field */

  src_line_->setPlaceholderText("Source File");
  dst_line_->setPlaceholderText("Destination File");

  /* Put start button and error message in the same line */

  hbox_->addWidget(start_btn_);
  hbox_->addWidget(err_msg_);
  hbox_->addStretch();
  hbox_->setSpacing(10);
  hbox_->setContentsMargins(0, 0, 0, 0);

  /* Configure main layout */

  vbox_->addWidget(mode_btn_);
  vbox_->addWidget(src_line_);
  vbox_->addWidget(dst_line_);
  vbox_->addWidget(pw_line_);
  vbox_->addLayout(hbox_);
  vbox_->addStretch();
  vbox_->setSpacing(10);
  vbox_->setContentsMargins(10, 10, 10, 10);

  setLayout(vbox_);

  /* Connect encryption/decryption start function to button */

  connect(start_btn_, &QPushButton::clicked, this, &InputGUI::OnStartClicked);
}

void InputGUI::SetErrMsg(const QString& msg) {
  err_msg_->setText(msg);
}

void InputGUI::OnStartClicked() {
  auto mode = mode_btn_->GetMode();

  if (!mode.has_value()) {
    err_msg_->setText("Mode is not selected");
    return;
  }

  if (src_line_->text().isEmpty()) {
    err_msg_->setText("Source file is not input");
    return;
  }

  if (dst_line_->text().isEmpty()) {
    err_msg_->setText("Destination file is not input");
    return;
  }

  Password tmp;

  if (pw_line_->Extract(tmp) == Result::kFailure) {
    err_msg_->setText("Cannot allocate secure memory for the password");
    return;
  }

  if (tmp.IsEmpty()) {
    err_msg_->setText("Password is not input");
    return;
  }

  pw_line_->Clear();

  CryptoRequest req{ .mode = mode.value(), .src = src_line_->text(), .dst = dst_line_->text(), .pw = std::move(tmp) };

  emit StartRequested(req);
}
