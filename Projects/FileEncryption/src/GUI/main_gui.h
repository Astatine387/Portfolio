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

#include "GUI/crypto_wrapper.h"
#include "GUI/input_gui.h"
#include "GUI/progress_gui.h"

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
  ~MainGUI();

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
  void OnWorkFinished(const QString& msg, bool should_delete);

  /**
   * @brief	Clean resources on worker thread finished
   */
  void OnThreadFinished();

  /**
   * @brief	Clean resources on close button clicked
   */
  void OnCloseRequested();

 private:
  FILE *src_file_ = nullptr, *dst_file_ = nullptr;
  InputGUI* input_gui_;
  ProgressGUI* prg_gui_;
  QStackedWidget* widget_;
  QThread* thread_;
  QVBoxLayout* vbox_;
  CryptoRequest req_;
  CryptoWrapper* wrapper_;
  bool should_delete_ = false;  // Destination file deletion flag for cancellation or failure

  /**
   * @brief   Open file pointers
   * @return  0 on success, 1 on error
   */
  int OpenFiles();

  /**
   * @brief   Clean all resources
   */
  void Clean();

  /**
   * @brief   Clean file pointers
   */
  void CloseFiles();
};