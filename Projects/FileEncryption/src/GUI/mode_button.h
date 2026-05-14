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
   * @return  0 for encrypt, 1 for decrypt, -1 if neither is selected
   */
  int GetMode();

 private:
  QButtonGroup* btn_group_;
  QHBoxLayout* hbox_;
  QRadioButton* enc_btn_;
  QRadioButton* dec_btn_;
};