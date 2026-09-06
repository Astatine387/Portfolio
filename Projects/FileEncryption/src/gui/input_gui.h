/**
 * @file	input_gui.h
 * @brief	User input window with start button
 * @author	Astatine387
 */

#pragma once

#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>
#include <QWidget>

#include "common/constants.h"
#include "gui/mode_button.h"
#include "gui/pw_line_edit.h"
#include "utils/password.h"

/**
 * @struct     CryptoRequest
 * @brief      Container for user input parameters
 *
 * Carries the password itself rather than a handle to it, so what leaves the input field is what reaches
 * the receiver. Qt hands a signal argument over as a const reference, so the receiver copies out of it
 * into locked memory of its own rather than moving.
 */
struct CryptoRequest {
  CryptoMode mode;
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
   *
   * Sender and receiver both live on the GUI thread, so the slot runs before the request it was handed
   * goes out of scope.
   */
  void StartRequested(const CryptoRequest& input);

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
