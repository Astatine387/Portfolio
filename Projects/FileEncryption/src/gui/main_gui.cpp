/**
 * @file    main_gui.cpp
 * @brief   Implementation of MainGUI class
 * @author  Astatine387
 */

#include "gui/main_gui.h"

#include <QCloseEvent>
#include <QFileInfo>
#include <atomic>
#include <memory>
#include <optional>
#include <utility>

#include "gui/crypto_wrapper.h"
#include "utils/platform.h"

MainGUI::MainGUI(QWidget* parent) : QWidget(parent) {
  /* Create layouts and components */

  input_gui_ = new InputGUI(this);
  progress_gui_ = new ProgressGUI(this);
  stk_widget_ = new QStackedWidget(this);
  vbox_ = new QVBoxLayout(this);

  /* Add GUIs to stacked widget for switching */

  stk_widget_->addWidget(input_gui_);
  stk_widget_->addWidget(progress_gui_);

  /* Configure layout */

  vbox_->addWidget(stk_widget_);
  vbox_->setContentsMargins(0, 0, 0, 0);

  setLayout(vbox_);
  setWindowTitle("FileEncryption");

  /* Connect functions to buttons */

  connect(input_gui_, &InputGUI::StartRequested, this,
          &MainGUI::OnStartRequested);
  connect(progress_gui_, &ProgressGUI::CloseRequested, this, &QWidget::close);
  connect(progress_gui_, &ProgressGUI::CancelRequested, this,
          &MainGUI::RequestCancel);
}

MainGUI::~MainGUI() {
  Clean();
}

void MainGUI::OnStartRequested(const CryptoRequest& input) {
  if (!input.mode.has_value()) {
    input_gui_->SetErrMsg("Mode is not selected");
    return;
  }

  src_path_ = input.src;
  dst_path_ = input.dst;

  if (ValidatePaths() == 0) {
    Password pw;

    if (pw.SetData(input.pw) == Result::kFailure) {
      input_gui_->SetErrMsg("Cannot allocate secure memory for the password");
      return;
    }

    /* Switch to progress GUI */

    stk_widget_->setCurrentWidget(progress_gui_);

    cancel_flag_ = std::make_shared<std::atomic<bool>>(false);

    /* Create worker thread */

    thread_ = new QThread(this);

    CryptoWrapper* wrapper = new CryptoWrapper(
        src_path_, dst_path_, std::move(pw), input.mode.value(), cancel_flag_);

    wrapper->moveToThread(thread_);

    /* Connect signals */

    connect(thread_, &QThread::started, wrapper, &CryptoWrapper::Run);
    connect(wrapper, &CryptoWrapper::ProgressUpdate, this,
            &MainGUI::OnProgressUpdated);
    connect(wrapper, &CryptoWrapper::PhaseChanged, this,
            &MainGUI::OnPhaseChanged);
    connect(wrapper, &CryptoWrapper::Finished, this, &MainGUI::OnWorkFinished);
    connect(wrapper, &CryptoWrapper::Finished, thread_, &QThread::quit);
    connect(thread_, &QThread::finished, this, &MainGUI::OnThreadFinished);
    connect(thread_, &QThread::finished, wrapper, &QObject::deleteLater);

    /* Start worker thread */

    thread_->start();
  }
}

void MainGUI::OnProgressUpdated(int perc, const QString& status) {
  if (closing_) {
    return;
  }

  progress_gui_->Update(perc, status);
}

void MainGUI::OnPhaseChanged(const QString& status, bool cancellable) {
  if (closing_) {
    return;
  }

  progress_gui_->SetPhase(status, cancellable);
}

void MainGUI::OnWorkFinished(const QString& msg) {
  if (closing_) {
    return;
  }

  progress_gui_->ShowResult(msg);
}

void MainGUI::OnThreadFinished() {
  if (thread_) {
    thread_->deleteLater();
    thread_ = nullptr;
  }

  cancel_flag_.reset();

  /* The close deferred in closeEvent happens here, now no worker is running */

  if (closing_) {
    close();
  }
}

void MainGUI::OnCloseRequested() {
  close();
}

void MainGUI::RequestCancel() {
  if (cancel_flag_) {
    cancel_flag_->store(true, std::memory_order_relaxed);
  }
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
  /* Cancel the worker and wait for it with no timeout */

  RequestCancel();

  if (thread_) {
    thread_->quit();
    thread_->wait();
  }
}

void MainGUI::closeEvent(QCloseEvent* event) {
  /* Request cancellation and keep the window alive in a busy state */

  if (thread_ && thread_->isRunning()) {
    RequestCancel();

    progress_gui_->ShowBusy("Finishing, please wait...\n");

    closing_ = true;
    event->ignore();

    return;
  }

  QWidget::closeEvent(event);
}
