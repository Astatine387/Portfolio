/**
 * @file    main_gui.h
 * @brief   Main GUI that controls entire workflow
 * @author  Astatine387
 */

#pragma once

#include <QStackedWidget>
#include <QThread>
#include <QVBoxLayout>
#include <QWidget>

#include "core/crypto_worker.h"
#include "gui/input_gui.h"
#include "gui/progress_gui.h"

/**
 * @brief   Main GUI that controls entire workflow
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
   * @brief   Destructor of MainGUI class
   */
  ~MainGUI() override;

 private slots:
  /**
   * @brief   Start encryption/decryption process
   * @param   input   User input parameters
   */
  void OnStartRequested(const CryptoRequest& input);

  /**
   * @brief   Update progress bar and status message
   * @param   perc    Progress percentage
   * @param   status  Status message
   */
  void OnProgressUpdated(int perc, const QString& status);

  /**
   * @brief   Show the current phase and offer cancelling
   * @param   status        Message describing what the run is doing now
   * @param   cancellable   Whether cancelling would end the run early
   */
  void OnPhaseChanged(const QString& status, bool cancellable);

  /**
   * @brief   Show the result, unless the window is already closing
   * @param   msg             Result message
   */
  void OnWorkFinished(const QString& msg);

  /**
   * @brief   Clean resources on worker thread finished
   */
  void OnThreadFinished();

  /**
   * @brief   Clean resources on close button clicked
   */
  void OnCloseRequested();

  /**
   * @brief   Raise the shared cancellation flag for the running worker
   */
  void RequestCancel();

 private:
  CryptoWorker::CancelFlag cancel_flag_;
  InputGUI* input_gui_ = nullptr;
  ProgressGUI* progress_gui_ = nullptr;
  QStackedWidget* stk_widget_ = nullptr;
  QString src_path_;
  QString dst_path_;
  QThread* thread_ = nullptr;
  QVBoxLayout* vbox_ = nullptr;
  bool closing_ = false;  // Whether a close is requested and suspended

  /**
   * @brief   Check the file paths are valid
   * @return  0 on valid, 1 on invalid
   */
  int ValidatePaths();

  /**
   * @brief   Wait for a running worker to finish on forced shutdown
   */
  void Clean();

  /**
   * @brief   Request cancel and defer the close until the worker returns
   * @param   event   Window close event
   */
  void closeEvent(QCloseEvent* event) override;
};
