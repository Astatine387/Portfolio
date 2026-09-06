/**
 * @file	mode_button.cpp
 * @brief	Implementation of ModeButton class
 * @author	Astatine387
 */

#include "mode_button.h"

#include <optional>

#include "common/constants.h"

ModeButton::ModeButton(QWidget* parent) : QWidget(parent) {
  /* Create layout and components */

  hbox_ = new QHBoxLayout;
  enc_btn_ = new QRadioButton("Encrypt");
  dec_btn_ = new QRadioButton("Decrypt");

  /* Neither is selected by default, so GetMode has a third answer and the caller can refuse to start
   * rather than run a direction the user never picked */

  enc_btn_->setChecked(false);
  dec_btn_->setChecked(false);

  /* Group buttons for mutual exclusion */

  btn_group_ = new QButtonGroup(this);
  btn_group_->addButton(enc_btn_, 0);
  btn_group_->addButton(dec_btn_, 1);
  btn_group_->setExclusive(true);

  /* Configure layout */

  hbox_->addWidget(enc_btn_);
  hbox_->addWidget(dec_btn_);
  hbox_->addStretch();
  hbox_->setSpacing(10);
  hbox_->setContentsMargins(0, 0, 0, 0);

  setLayout(hbox_);
}

std::optional<CryptoMode> ModeButton::GetMode() {
  if (enc_btn_->isChecked()) {
    return CryptoMode::kEncrypt;
  }

  if (dec_btn_->isChecked()) {
    return CryptoMode::kDecrypt;
  }

  return std::nullopt;
}
