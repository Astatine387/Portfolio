/**
 * @file	login_gui.cpp
 * @brief	Implementation of LoginGUI class
 * @author	Astatine387
 */

#include "gui/login_gui.h"

#include <QFileDialog>

LoginGUI::LoginGUI(QWidget* parent) : QWidget(parent) {
  /* Create layout and components */

  new_btn_ = new QPushButton("New");
  open_btn_ = new QPushButton("Open");
  hbox_ = new QHBoxLayout;

  /* Configure layout */

  hbox_->addStretch();
  hbox_->addWidget(new_btn_);
  hbox_->addStretch();
  hbox_->addWidget(open_btn_);
  hbox_->addStretch();

  setLayout(hbox_);

  /* Connect functions to buttons */

  connect(new_btn_, &QPushButton::clicked, this, &LoginGUI::OnNewClicked);
  connect(open_btn_, &QPushButton::clicked, this, &LoginGUI::OnOpenClicked);
}

void LoginGUI::OnNewClicked() {
  QString path = QFileDialog::getSaveFileName(this, "Create New Vault", "", "Vault Files (*.vault)");

  if (!path.isEmpty())
    emit VaultSelected(VaultAction::kCreate, path);
}

void LoginGUI::OnOpenClicked() {
  QString path = QFileDialog::getOpenFileName(this, "Open Vault", "", "Vault Files (*.vault)");

  if (!path.isEmpty())
    emit VaultSelected(VaultAction::kOpen, path);
}
