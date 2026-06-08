/**
 * @file	pw_line_edit.h
 * @brief	Password input window with show/hide toggle
 * @author	Astatine387
 */

#pragma once

#include <QHBoxLayout>
#include <QLineEdit>
#include <QPushButton>
#include <QWidget>

#include "Utils/password.h"

/**
 * @class   PWLineEdit
 * @brief   Password input window with show/hide toggle
 */
class PWLineEdit : public QWidget {
  Q_OBJECT

 public:
  /**
   * @brief   Constructor of PWLineEdit class
   * @param   parent  Parent widget
   */
  explicit PWLineEdit(QWidget* parent = nullptr);

  /**
   * @brief   Extract data from the input line to Password class
   * @param   pw  Destination
   * @return  kSuccess on success, kFailure on failure (exceeds MAX_SIZE)
   */
  Result Extract(Password& pw);

  /**
   * @brief   Clear the input field
   */
  void Clear();

  /**
   * @brief	Set password data to the input field
   * @param	pw	Source password
   */
  void SetPassword(const Password& pw);

 private slots:
  /**
   * @brief   Signal when toggle masking button clicked
   */
  void ToggleMask();

 private:
  QHBoxLayout* hbox_;
  QLineEdit* pw_line_;
  QPushButton* mask_btn_;
};