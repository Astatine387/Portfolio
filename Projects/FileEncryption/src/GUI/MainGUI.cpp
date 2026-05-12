/**
 * @file	MainGUI.cpp
 * @brief	Implementation of MainGUI class
 * @author	Astatine387
 */

#include "GUI/MainGUI.h"

#include "Utils/library.h"

#include <QFileInfo>

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

  connect(input_gui_, &InputGUI::startRequested, this, &MainGUI::onStartRequested);
  connect(prg_gui_, &ProgressGUI::closeRequested, this, &QWidget::close);
}

MainGUI::~MainGUI() {
  Clean();
}

UserInput MainGUI::GetUserInput() {
  return user_input_;
}

bool MainGUI::IsInputValid() {
  return user_input_.valid;
}

void MainGUI::onStartRequested(const UserInput& input) {
  /* Copy user input parameters */

  user_input_.valid = input.valid;
  user_input_.mode = input.mode;
  user_input_.src = input.src;
  user_input_.dst = input.dst;
  user_input_.pw.SetData(input.pw);

  if (OpenFiles() == 0) {
    /* Switch to progress window */

    widget_->setCurrentWidget(prg_gui_);

    /* Create worker thread */

    thread_ = new QThread(this);
    worker_ = new Worker(src_file_, dst_file_, user_input_.dst, user_input_.pw, user_input_.mode);
    worker_->moveToThread(thread_);

    /* Connect signals */

    connect(thread_, &QThread::started, worker_, &Worker::work);
    connect(worker_, &Worker::progressUpdate, this, &MainGUI::onProgressUpdated);
    connect(worker_, &Worker::finished, this, &MainGUI::onWorkFinished);
    connect(prg_gui_, &ProgressGUI::cancelRequested, worker_, &Worker::requestCancel,
            Qt::DirectConnection);
    connect(worker_, &Worker::finished, thread_, &QThread::quit);
    connect(thread_, &QThread::finished, this, &MainGUI::onThreadFinished);

    /* Start worker thread */

    thread_->start();
  }
}

void MainGUI::onProgressUpdated(int perc, const QString& status) {
  prg_gui_->Update(perc, status);
}

void MainGUI::onWorkFinished(const QString& msg, bool should_delete) {
  prg_gui_->ShowResult(msg);
  this->should_delete_ = should_delete;
}

void MainGUI::onThreadFinished() {
  Clean();
}

void MainGUI::onCloseRequested() {
  close();
}

int MainGUI::OpenFiles() {
  QFileInfo srcInfo(user_input_.src);
  QFileInfo dstInfo(user_input_.dst);

  CloseFiles();

  OpenFile(&src_file_, user_input_.src, "rb");

  if (src_file_ == nullptr) {
    input_gui_->SetErrMsg("ERROR: Failed to open source file");
    return 1;
  }

  if (srcInfo.canonicalFilePath() == dstInfo.canonicalFilePath()) {
    input_gui_->SetErrMsg("Source and destination cannot be the same");
    return 1;
  }

  if (FileExists(user_input_.dst)) {
    input_gui_->SetErrMsg("Destination file already exists");
    return 1;
  }

  OpenFile(&dst_file_, user_input_.dst, "wb+");

  if (dst_file_ == nullptr) {
    input_gui_->SetErrMsg("ERROR: Failed to create destination file");
    return 1;
  }

  return 0;
}

void MainGUI::Clean() {
  if (thread_ && thread_->isRunning()) {
    if (worker_) {
      worker_->requestCancel();
    }

    thread_->quit();

    if (!thread_->wait(5000)) {
      thread_->terminate();
      thread_->wait();
    }
  }

  if (worker_) {
    worker_->deleteLater();
    worker_ = nullptr;
  }

  if (thread_) {
    thread_->deleteLater();
    thread_ = nullptr;
  }

  CloseFiles();

  if (should_delete_) {
    RemoveFile(user_input_.dst);
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