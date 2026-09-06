/**
 * @file	progress_gui.h
 * @brief	Progress bar widget with cancel and close buttons
 * @author	Astatine387
 */

#pragma once

#include <QHBoxLayout>
#include <QLabel>
#include <QProgressBar>
#include <QPushButton>
#include <QVBoxLayout>
#include <QWidget>

/**
 * @class	ProgressGUI
 * @brief	Progress bar widget with cancel and close buttons
 */
class ProgressGUI : public QWidget {
  Q_OBJECT

 public:
  /**
   * @brief   Constructor of ProgressGUI class
   * @param   parent  Parent widget
   */
  explicit ProgressGUI(QWidget* parent = nullptr);

  /**
   * @brief   Check whether the process is cancelled by user
   * @return  true if cancel button is clicked
   *
   * Latched once set, so a cancel cannot be lost between the click and whenever it is asked about.
   */
  bool IsCancelled();

  /**
   * @brief   Update progress bar and status message
   * @param   perc     Progress percentage
   * @param   status  Status message
   */
  void Update(int perc, const QString& status);

  /**
   * @brief   Show result and enable close button
   * @param   msg     result message
   */
  void ShowResult(const QString& msg);

  /**
   * @brief   Show the shutdown busy state while the worker drains
   * @param   msg     Status message
   *
   * The end of the window's life, not a state it comes back from: cancelling is disabled and the bar
   * stops carrying a percentage, because the worker only stops between chunks and there is nothing left
   * to ask of it.
   */
  void ShowBusy(const QString& msg);

 signals:
  /**
   * @brief   Signal when cancel button clicked
   */
  void CancelRequested();

  /**
   * @brief   Signal when close button clicked
   */
  void CloseRequested();

 private slots:
  /**
   * @brief   Set cancellation flag and emit cancellation signal
   */
  void OnCancelClicked();

 private:
  QLabel* prg_label_;
  QProgressBar* prg_bar_;
  QPushButton* cancel_btn_;
  QPushButton* close_btn_;
  QHBoxLayout* hbox_;
  QVBoxLayout* vbox_;
  bool cancelled_ = false;
};
