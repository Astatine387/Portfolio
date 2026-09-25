/**
 * @file	login_gui.cpp
 * @brief	Implementation of LoginGUI class
 * @author	Astatine387
 */

#include "gui/login_gui.h"

#include <QFileDialog>
#include <QFileInfo>
#include <QMessageBox>

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
  /* DontConfirmOverwrite, because the dialog's own prompt asks whether to replace the file and the core answers that
   * question the other way: NewVault refuses a path that is taken rather than writing over it. Left in, the prompt
   * would offer a "yes" that nothing downstream honours. */

  QString path = QFileDialog::getSaveFileName(this, "Create New Vault", "", "Vault Files (*.vault)", nullptr,
                                              QFileDialog::DontConfirmOverwrite);

  if (path.isEmpty()) {
    return;
  }

  /* The core refuses a taken path as well, and has to: the master password dialog and the derivation that follows it
   * sit between this check and the create. This one is here so that the refusal arrives while the name is still
   * being chosen, rather than after a password has been typed and waited on. */

  if (QFileInfo::exists(path)) {
    QMessageBox::warning(this, "File Exists",
                         "A file already exists at this path. Choose another name, or delete the file yourself "
                         "first.");
    return;
  }

  emit VaultSelected(VaultAction::kCreate, path);
}

void LoginGUI::OnOpenClicked() {
  QString path = QFileDialog::getOpenFileName(this, "Open Vault", "", "Vault Files (*.vault)");

  if (!path.isEmpty())
    emit VaultSelected(VaultAction::kOpen, path);
}
