/**
 * @file	InputGUI.h
 * @brief	User input window with start button
 * @author	Astatine387
 */

#pragma once

#include "GUI/ModeButton.h"
#include "GUI/PWLineEdit.h"
#include "Utils/Password.h"

#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>
#include <QWidget>

/**
 * @struct     UserInput
 * @brief      Container for user input parameters
 */
struct UserInput {
  bool valid = false;
  int mode = -1;
  QString src;
  QString dst;
  Password pw;
};

/**
 * @class   InputGUI
 * @brief   User input window with start button
 */
class InputGUI : public QWidget {
  Q_OBJECT

 public:
  /**
   * @brief   Constructor of InputGUI class
   * @param   parent  Parent widget
   */
  explicit InputGUI(QWidget* parent = nullptr);

  /**
   * @brief   Display error message
   * @param   msg     error message string
   */
  void SetErrMsg(const QString& msg);

 signals:
  /**
   * @brief   Signal when start button clicked
   * @param   input   User inputs
   */
  void StartRequested(const UserInput& input);

 private slots:
  /**
   * @brief   Check the user input parameters are valid and start process
   */
  void OnStartClicked();

 private:
  ModeButton* mode_btn_;
  PWLineEdit* pw_line_;
  QLineEdit* src_line_;  // Source file input field
  QLineEdit* dst_line_;  // Destination file input field
  QPushButton* start_btn_;
  QLabel* err_msg_;    // Label to display error messages
  QHBoxLayout* hbox_;  // Layout for start button and error message
  QVBoxLayout* vbox_;
};