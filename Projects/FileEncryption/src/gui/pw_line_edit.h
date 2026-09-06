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

#include "utils/password.h"

/**
 * @class	PWLineEdit
 * @brief	Password input window with show/hide toggle
 */
class PWLineEdit : public QWidget {
  Q_OBJECT

 public:
  /**
   * @brief		Constructor of PWLineEdit class
   * @param		parent  Parent widget
   */
  explicit PWLineEdit(QWidget* parent = nullptr);

  /**
   * @brief		Clear the input field
   */
  void Clear();

  /**
   * @brief		Extract data from the input line to Password class
   * @param		pw	Destination
   * @return	kSuccess on success, kFailure when secure allocation fails
   *
   * Clears the field as part of extracting, so the widget stops being somewhere the password is kept.
   * The copies this code can reach are wiped; a buffer Qt has already reallocated behind the QString
   * cannot be, which is the limit of what the GUI side can promise.
   */
  [[nodiscard]] Result Extract(Password& pw);

 private slots:
  /**
   * @brief		Signal when toggle masking button clicked
   */
  void ToggleMask();

 private:
  QHBoxLayout* hbox_;
  QLineEdit* pw_line_;
  QPushButton* mask_btn_;
};
