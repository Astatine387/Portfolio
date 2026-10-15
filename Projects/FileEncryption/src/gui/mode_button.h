/**
 * @file    mode_button.h
 * @brief   Encrypt/decrypt mode selection widget
 * @author  Astatine387
 */

#pragma once

#include <QButtonGroup>
#include <QHBoxLayout>
#include <QRadioButton>
#include <QWidget>
#include <optional>

#include "common/constants.h"

/**
 * @brief   Encryption/decryption mode selection widget
 *
 * Neither button starts selected.
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
   * @return  CryptoMode::kEncrypt or kDecrypt, or std::nullopt
   */
  std::optional<CryptoMode> GetMode();

 private:
  QButtonGroup* btn_group_;
  QHBoxLayout* hbox_;
  QRadioButton* enc_btn_;
  QRadioButton* dec_btn_;
};
