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

#include "core/crypto_worker.h"
#include "gui/input_gui.h"
#include "gui/progress_gui.h"

/**
 * @class   MainGUI
 * @brief   Main GUI class that orchestrates entire workflow
 *
 * Owns the worker thread and is the only place that knows a worker exists. Everything after the start
 * button arrives as a queued signal, so no slot here ever waits on the work; the one exception is the
 * forced shutdown in the destructor, where there is no event loop left to defer to.
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
   * @brief	Show the current phase and offer cancelling only where it would work
   * @param   status        Message describing what the run is doing now
   * @param   cancellable   Whether cancelling would end the run early
   */
  void OnPhaseChanged(const QString& status, bool cancellable);

  /**
   * @brief	Show result and set deletion flag
   * @param   msg             Result message
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

  /**
   * @brief	Raise the shared cancellation flag for the running worker
   */
  void RequestCancel();

 private:
  /* GUI-thread state throughout. The worker gets its own copies of the paths and the password and its
   * own share of the cancellation flag, so nothing below is read from the other thread. */

  CryptoWorker::CancelFlag cancel_flag_;
  InputGUI* input_gui_ = nullptr;
  ProgressGUI* prg_gui_ = nullptr;
  QStackedWidget* widget_ = nullptr;
  QString src_path_;
  QString dst_path_;
  QThread* thread_ = nullptr;
  QVBoxLayout* vbox_ = nullptr;
  bool closing_ = false;  // Whether a close has been deferred until the worker returns

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
