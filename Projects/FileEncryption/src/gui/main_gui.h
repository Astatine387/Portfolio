/**
 * @file	main_gui.h
 * @brief	Main GUI class that controls entire workflow
 * @author	Astatine387
 */

#pragma once

#include <QStackedWidget>
#include <QThread>
#include <QVBoxLayout>
#include <QWidget>

#include "gui/crypto_wrapper.h"
#include "gui/input_gui.h"
#include "gui/progress_gui.h"

/**
 * @class   MainGUI
 * @brief   Main GUI class that orchestrates entire workflow
 */
class MainGUI : public QWidget {
  Q_OBJECT

 public:
  /**
   * @brief   Constructor of MainGUI class
   * @param   parent  Parent widget
   */
  explicit MainGUI(QWidget* parent = nullptr);

  /**
   * @brief	Destructor of MainGUI class
   */
  ~MainGUI() override;

  /**
   * @brief   Get the current user input
   * @return  Current user input
   */
  CryptoRequest GetUserInput();

 private slots:
  /**
   * @brief	Start encryption/decryption process
   * @param   input   User input parameters
   */
  void OnStartRequested(const CryptoRequest& input);

  /**
   * @brief	Update progress bar and status message
   * @param   perc    Progress percentage
   * @param   status  Status message
   */
  void OnProgressUpdated(int perc, const QString& status);

  /**
   * @brief	Show result and set deletion flag
   * @param   msg             Result message
   * @param   shouldDelete    Destination file deletion flag value
   */
  void OnWorkFinished(const QString& msg);

  /**
   * @brief	Clean resources on worker thread finished
   */
  void OnThreadFinished();

  /**
   * @brief	Clean resources on close button clicked
   */
  void OnCloseRequested();

 private:
  CryptoWrapper* wrapper_ = nullptr;
  InputGUI* input_gui_ = nullptr;
  ProgressGUI* prg_gui_ = nullptr;
  QStackedWidget* widget_ = nullptr;
  QThread* thread_ = nullptr;
  QVBoxLayout* vbox_ = nullptr;
  CryptoRequest req_;

  /**
   * @brief   Check the file paths are valid
   * @return  0 on valid, 1 on invalid
   */
  int ValidatePaths();

  /**
   * @brief   Clean all resources
   */
  void Clean();
};