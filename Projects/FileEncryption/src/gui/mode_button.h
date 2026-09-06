/**
 * @file	mode_button.h
 * @brief	Encrypt/decrypt mode selection widget
 * @author	Astatine387
 */

#pragma once

#include <QButtonGroup>
#include <QHBoxLayout>
#include <QRadioButton>
#include <QWidget>
#include <optional>

#include "common/constants.h"

/**
 * @class   ModeButton
 * @brief   Encryption/decryption mode selection widget
 */
class ModeButton : public QWidget {
 public:
  /**
   * @brief   Constructor of ModeButton class
   * @param   parent  Parent widget
   */
  explicit ModeButton(QWidget* parent = nullptr);

  /**
   * @brief   Get the currently selected mode
   * @return  CryptoMode::kEncrypt or kDecrypt, or std::nullopt if neither is selected
   *
   * Neither button starts selected, so "nothing chosen yet" is a state the caller has to handle rather
   * than a default that would quietly pick one of the two on the user's behalf.
   */
  std::optional<CryptoMode> GetMode();

 private:
  QButtonGroup* btn_group_;
  QHBoxLayout* hbox_;
  QRadioButton* enc_btn_;
  QRadioButton* dec_btn_;
};
