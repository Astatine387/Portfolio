/**
 * @file	main_gui.cpp
 * @brief	Implementation of MainGUI class
 * @author	Astatine387
 */

#include "gui/main_gui.h"

#include <QCloseEvent>
#include <QFileInfo>
#include <atomic>
#include <memory>
#include <utility>

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
  connect(prg_gui_, &ProgressGUI::CancelRequested, this, &MainGUI::RequestCancel);
}

MainGUI::~MainGUI() {
  Clean();
}

void MainGUI::OnStartRequested(const CryptoRequest& input) {
  /* ValidatePaths and the worker both read the members rather than the request, which does not outlive
   * this call */

  src_path_ = input.src;
  dst_path_ = input.dst;

  if (ValidatePaths() == 0) {
    Password pw;

    if (pw.SetData(input.pw) == Result::kFailure) {
      input_gui_->SetErrMsg("Cannot allocate secure memory for the password");
      return;
    }

    /* Switch to progress window */

    widget_->setCurrentWidget(prg_gui_);

    /* Shared rather than owned, so cancelling stays safe whichever side lets go of it first */

    cancel_flag_ = std::make_shared<std::atomic<bool>>(false);

    /* Create worker thread. The wrapper is built here but given away immediately: after moveToThread
     * every one of its slots, Run included, runs on the worker thread. It gets no parent, because a
     * parent would have to live on the same thread as the child. */

    thread_ = new QThread(this);

    CryptoWrapper* wrapper = new CryptoWrapper(src_path_, dst_path_, std::move(pw), input.mode, cancel_flag_);

    wrapper->moveToThread(thread_);

    /* Connect signals. Both Finished connections are queued into this thread in the order they are made,
     * so the result reaches the window before the thread is asked to stop. */

    connect(thread_, &QThread::started, wrapper, &CryptoWrapper::Run);
    connect(wrapper, &CryptoWrapper::ProgressUpdate, this, &MainGUI::OnProgressUpdated);
    connect(wrapper, &CryptoWrapper::PhaseChanged, this, &MainGUI::OnPhaseChanged);
    connect(wrapper, &CryptoWrapper::Finished, this, &MainGUI::OnWorkFinished);
    connect(wrapper, &CryptoWrapper::Finished, thread_, &QThread::quit);
    connect(thread_, &QThread::finished, this, &MainGUI::OnThreadFinished);

    /* Nothing else owns the wrapper. Hanging its deletion off the thread's own finished signal is what
     * guarantees it outlives the code running on that thread. */

    connect(thread_, &QThread::finished, wrapper, &QObject::deleteLater);

    /* Start worker thread */

    thread_->start();
  }
}

void MainGUI::OnProgressUpdated(int perc, const QString& status) {
  /* Once closeEvent has deferred a close, reports that were already queued would paint over the busy
   * message and the window is on its way out regardless */

  if (closing_) {
    return;
  }

  prg_gui_->Update(perc, status);
}

void MainGUI::OnPhaseChanged(const QString& status, bool cancellable) {
  /* Same reason as above, and one more: closeEvent has already disabled cancelling for good, and a
   * phase report queued before it would hand the button back to a window that is on its way out */

  if (closing_) {
    return;
  }

  prg_gui_->SetPhase(status, cancellable);
}

void MainGUI::OnWorkFinished(const QString& msg) {
  if (closing_) {
    return;
  }

  prg_gui_->ShowResult(msg);
}

void MainGUI::OnThreadFinished() {
  /* Reached from the thread's own finished signal, so the thread object cannot be deleted outright */

  if (thread_) {
    thread_->deleteLater();
    thread_ = nullptr;
  }

  cancel_flag_.reset();

  /* The close deferred in closeEvent happens here, now that no worker is left running */

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
  /* Last-resort forced-quit path; cancel the worker and wait for it with no timeout. Running from the
   * destructor, there is no event loop left to defer to, and the wait is unbounded because the worker
   * only looks at the flag between chunks. */

  RequestCancel();

  if (thread_) {
    thread_->quit();
    thread_->wait();
  }
}

void MainGUI::closeEvent(QCloseEvent* event) {
  /* Request cancellation and keep the window alive in a busy state. Letting the close through would
   * destroy the QThread this widget owns while it is still running, which Qt terminates the process
   * over; OnThreadFinished closes the window instead, once the worker has actually returned. */

  if (thread_ && thread_->isRunning()) {
    RequestCancel();

    prg_gui_->ShowBusy("Finishing, please wait...\n");

    closing_ = true;
    event->ignore();

    return;
  }

  QWidget::closeEvent(event);
}
