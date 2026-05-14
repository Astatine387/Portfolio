/**
 * @file	ProgressGUI.cpp
 * @brief	Implementation of ProgressGUI class
 * @author	Astatine387
 */

#include "GUI/ProgressGUI.h"

ProgressGUI::ProgressGUI(QWidget* parent) : QWidget(parent), cancelled_(false) {
  /* Create layouts and components */

  prg_label_ = new QLabel("Initializing...\n");
  prg_bar_ = new QProgressBar;
  cancel_btn_ = new QPushButton("Cancel");
  close_btn_ = new QPushButton("Close");
  hbox_ = new QHBoxLayout;
  vbox_ = new QVBoxLayout;

  /* Configure progress bar */

  prg_bar_->setRange(0, 100);
  prg_bar_->setValue(0);

  /* Hide close button during the process */

  close_btn_->hide();

  /* Configure layouts */

  hbox_->addWidget(cancel_btn_);
  hbox_->addWidget(close_btn_);
  hbox_->addStretch();
  hbox_->setSpacing(10);
  hbox_->setContentsMargins(0, 0, 0, 0);

  vbox_->addWidget(prg_label_);
  vbox_->addWidget(prg_bar_);
  vbox_->addStretch();
  vbox_->addLayout(hbox_);
  vbox_->setSpacing(10);
  vbox_->setContentsMargins(10, 10, 10, 10);

  setLayout(vbox_);

  /* Connect cancel/close functions to each button */

  connect(cancel_btn_, &QPushButton::clicked, this,
          &ProgressGUI::OnCancelClicked);
  connect(close_btn_, &QPushButton::clicked, this,
          &ProgressGUI::CloseRequested);
}

bool ProgressGUI::IsCancelled() {
  return cancelled_;
}

void ProgressGUI::Update(int val, const QString& status) {
  prg_bar_->setValue(val);
  prg_label_->setText(status);
}

void ProgressGUI::ShowResult(const QString& msg) {
  prg_label_->setText(msg);
  cancel_btn_->hide();
  close_btn_->show();
}

void ProgressGUI::OnCancelClicked() {
  cancelled_ = true;
  emit CancelRequested();
}