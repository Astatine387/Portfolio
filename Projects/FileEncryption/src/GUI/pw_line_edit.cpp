/**
 * @file	pw_line_edit.cpp
 * @brief	Implementation of PWLineEdit class
 * @author	Astatine387
 */

#include "GUI/pw_line_edit.h"

#include "Common/constants.h"
#include "Utils/platform.h"

PWLineEdit::PWLineEdit(QWidget* parent) : QWidget(parent) {
  /* Create layout and components */

  hbox_ = new QHBoxLayout;
  mask_btn_ = new QPushButton("See");
  pw_line_ = new QLineEdit;

  /* Set placeholder text that indicates password field */

  pw_line_->setPlaceholderText("Password");
  pw_line_->setEchoMode(QLineEdit::Password);

  /* Configure masking toggle button */

  mask_btn_->setFixedSize(
      static_cast<int>(45 * kFontScale),
      static_cast<int>(pw_line_->sizeHint().height() * kFontScale));

  /* Configure layout */

  hbox_->addWidget(pw_line_);
  hbox_->addWidget(mask_btn_);
  hbox_->setSpacing(10);
  hbox_->setContentsMargins(0, 0, 0, 0);

  /* Connect masking toggle function to button */

  connect(mask_btn_, &QPushButton::clicked, this, &PWLineEdit::ToggleMask);

  setLayout(hbox_);
}

void PWLineEdit::Clear() {
  pw_line_->clear();
}

void PWLineEdit::Extract(Password& pw) {
  QByteArray data = pw_line_->text().toUtf8();
  int size = data.size();

  Lock(data.data(), size);

  pw.SetData(data.constData(), size);

  Wipe(data.data(), size);
  Unlock(data.data(), size);

  pw_line_->clear();
}

void PWLineEdit::ToggleMask() {
  if (pw_line_->echoMode() == QLineEdit::Password) {
    pw_line_->setEchoMode(QLineEdit::Normal);
    mask_btn_->setText("Hide");
  }
  else {
    pw_line_->setEchoMode(QLineEdit::Password);
    mask_btn_->setText("See");
  }
}