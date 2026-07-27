/**
 * @file	main_gui.cpp
 * @brief	Implementation of MainGUI class
 * @author	Astatine387
 */

#include "gui/main_gui.h"

#include <QCloseEvent>
#include <QFileInfo>

#include "gui/crypto_wrapper.h"
#include "utils/platform.h"

MainGUI::MainGUI(QWidget* parent) : QWidget(parent) {
  /* Create layouts and components */

  input_gui_ = new InputGUI(this);
  prg_gui_ = new ProgressGUI(this);
  widget_ = new QStackedWidget(this);
  vbox_ = new QVBoxLayout(this);

  /* Add GUIs to stacked widget for switching */

  widget_->addWidget(input_gui_);
  widget_->addWidget(prg_gui_);

  /* Configure layout */

  vbox_->addWidget(widget_);
  vbox_->setContentsMargins(0, 0, 0, 0);

  setLayout(vbox_);
  setWindowTitle("FileEncryption");

  /* Connect functions to buttons */

  connect(input_gui_, &InputGUI::StartRequested, this, &MainGUI::OnStartRequested);
  connect(prg_gui_, &ProgressGUI::CloseRequested, this, &QWidget::close);
}

MainGUI::~MainGUI() {
  Clean();
}

void MainGUI::OnStartRequested(const CryptoRequest& input) {
  /* Copy paths */

  src_path_ = input.src;
  dst_path_ = input.dst;

  if (ValidatePaths() == 0) {
    /* Switch to progress window */

    widget_->setCurrentWidget(prg_gui_);

    /* Create worker thread */

    thread_ = new QThread(this);
    wrapper_ = new CryptoWrapper(src_path_, dst_path_, input.pw, input.mode);
    wrapper_->moveToThread(thread_);

    /* Connect signals */

    connect(thread_, &QThread::started, wrapper_, &CryptoWrapper::Run);
    connect(wrapper_, &CryptoWrapper::ProgressUpdate, this, &MainGUI::OnProgressUpdated);
    connect(wrapper_, &CryptoWrapper::Finished, this, &MainGUI::OnWorkFinished);
    connect(prg_gui_, &ProgressGUI::CancelRequested, wrapper_, &CryptoWrapper::RequestCancel, Qt::DirectConnection);
    connect(wrapper_, &CryptoWrapper::Finished, thread_, &QThread::quit);
    connect(thread_, &QThread::finished, this, &MainGUI::OnThreadFinished);

    /* Delete the worker when the thread finishes */

    connect(thread_, &QThread::finished, wrapper_, &QObject::deleteLater);

    /* Start worker thread */

    thread_->start();
  }
}

void MainGUI::OnProgressUpdated(int perc, const QString& status) {
  /* Keep the shutdown busy state visible once a close has been requested */

  if (closing_) {
    return;
  }

  prg_gui_->Update(perc, status);
}

void MainGUI::OnWorkFinished(const QString& msg) {
  wrapper_ = nullptr;

  /* During shutdown keep the busy state; the window closes once the worker returns */

  if (closing_) {
    return;
  }

  prg_gui_->ShowResult(msg);
}

void MainGUI::OnThreadFinished() {
  /* The worker has returned; the wrapper is deleted by its finished/deleteLater connection */

  if (thread_) {
    thread_->deleteLater();
    thread_ = nullptr;
  }

  wrapper_ = nullptr;

  /* A close was suspended until the worker finished: now close for real */

  if (closing_) {
    close();
  }
}

void MainGUI::OnCloseRequested() {
  close();
}

int MainGUI::ValidatePaths() {
  QFileInfo src_info(src_path_);
  QFileInfo dst_info(dst_path_);

  if (!src_info.exists()) {
    input_gui_->SetErrMsg("Source file does not exist");
    return 1;
  }

  if (src_info.canonicalFilePath() == dst_info.canonicalFilePath()) {
    input_gui_->SetErrMsg("Source and destination cannot be the same");
    return 1;
  }

  if (dst_info.exists()) {
    input_gui_->SetErrMsg("Destination file already exists");
    return 1;
  }

  return 0;
}

void MainGUI::Clean() {
  /* Last-resort forced-quit path; cancel the worker and wait for it with no timeout */

  if (thread_ && thread_->isRunning()) {
    if (wrapper_) {
      wrapper_->RequestCancel();
    }

    thread_->quit();
    thread_->wait();
  }
}

void MainGUI::closeEvent(QCloseEvent* event) {
  /* Request cancellation and keep the window alive in a busy state */

  if (thread_ && thread_->isRunning()) {
    if (wrapper_) {
      wrapper_->RequestCancel();
    }

    prg_gui_->ShowBusy("Finishing, please wait...\n");

    closing_ = true;
    event->ignore();

    return;
  }

  QWidget::closeEvent(event);
}