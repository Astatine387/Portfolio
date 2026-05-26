/**
 * @file	main_gui.cpp
 * @brief	Implementation of MainGUI class
 * @author	Astatine387
 */

#include "GUI/main_gui.h"

#include <QFileInfo>

#include "GUI/crypto_wrapper.h"
#include "Utils/platform.h"

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

CryptoRequest MainGUI::GetUserInput() {
  return req_;
}

void MainGUI::OnStartRequested(const CryptoRequest& input) {
  /* Copy user input parameters */

  req_.mode = input.mode;
  req_.src = input.src;
  req_.dst = input.dst;
  req_.pw.SetData(input.pw);

  if (OpenFiles() == 0) {
    /* Switch to progress window */

    widget_->setCurrentWidget(prg_gui_);

    /* Create worker thread */

    thread_ = new QThread(this);
    wrapper_ = new CryptoWrapper(src_file_, dst_file_, req_.dst, req_.pw, req_.mode);
    wrapper_->moveToThread(thread_);

    /* Connect signals */

    connect(thread_, &QThread::started, wrapper_, &CryptoWrapper::Run);
    connect(wrapper_, &CryptoWrapper::ProgressUpdate, this, &MainGUI::OnProgressUpdated);
    connect(wrapper_, &CryptoWrapper::Finished, this, &MainGUI::OnWorkFinished);
    connect(prg_gui_, &ProgressGUI::CancelRequested, wrapper_, &CryptoWrapper::RequestCancel, Qt::DirectConnection);
    connect(wrapper_, &CryptoWrapper::Finished, thread_, &QThread::quit);
    connect(thread_, &QThread::finished, this, &MainGUI::OnThreadFinished);

    /* Start worker thread */

    thread_->start();
  }
}

void MainGUI::OnProgressUpdated(int perc, const QString& status) {
  prg_gui_->Update(perc, status);
}

void MainGUI::OnWorkFinished(const QString& msg, bool should_delete) {
  prg_gui_->ShowResult(msg);
  this->should_delete_ = should_delete;
}

void MainGUI::OnThreadFinished() {
  Clean();
}

void MainGUI::OnCloseRequested() {
  close();
}

int MainGUI::OpenFiles() {
  QFileInfo src_info(req_.src);
  QFileInfo dst_info(req_.dst);

  CloseFiles();

  OpenFile(&src_file_, req_.src.toStdString(), "rb");

  if (src_file_ == nullptr) {
    input_gui_->SetErrMsg("ERROR: Failed to open source file");
    return 1;
  }

  if (src_info.canonicalFilePath() == dst_info.canonicalFilePath()) {
    input_gui_->SetErrMsg("Source and destination cannot be the same");
    return 1;
  }

  if (FileExists(req_.dst.toStdString())) {
    input_gui_->SetErrMsg("Destination file already exists");
    return 1;
  }

  OpenFile(&dst_file_, req_.dst.toStdString(), "wb+");

  if (dst_file_ == nullptr) {
    input_gui_->SetErrMsg("ERROR: Failed to create destination file");
    return 1;
  }

  return 0;
}

void MainGUI::Clean() {
  if (thread_ && thread_->isRunning()) {
    if (wrapper_) {
      wrapper_->RequestCancel();
    }

    thread_->quit();

    if (!thread_->wait(5000)) {
      thread_->terminate();
      thread_->wait();
    }
  }

  if (wrapper_) {
    wrapper_->deleteLater();
    wrapper_ = nullptr;
  }

  if (thread_) {
    thread_->deleteLater();
    thread_ = nullptr;
  }

  CloseFiles();

  if (should_delete_) {
    RemoveFile(req_.dst.toStdString());
    should_delete_ = false;
  }
}

void MainGUI::CloseFiles() {
  if (src_file_) {
    fclose(src_file_);
    src_file_ = nullptr;
  }

  if (dst_file_) {
    fclose(dst_file_);
    dst_file_ = nullptr;
  }
}