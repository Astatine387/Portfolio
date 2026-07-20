/**
 * @file	main_gui.cpp
 * @brief	Implementation of MainGUI class
 * @author	Astatine387
 */

#include "gui/main_gui.h"

#include <QApplication>
#include <QClipboard>
#include <QGuiApplication>

#include "gui/entry_interface.h"

MainGUI::MainGUI(QWidget* parent) : QWidget(parent) {
  /* Create layouts and components */

  change_pw_gui_ = new ChangePWGUI(this);
  entry_gui_ = new EntryGUI(this);
  list_gui_ = new ListGUI(this);
  login_gui_ = new LoginGUI(this);
  pw_gui_ = new PasswordGUI(this);
  stack_ = new QStackedWidget(this);
  vbox_ = new QVBoxLayout(this);

  /* Add GUIs to stacked widget for switching */

  stack_->addWidget(login_gui_);
  stack_->addWidget(pw_gui_);
  stack_->addWidget(list_gui_);

  /* Configure layout */

  vbox_->addWidget(stack_);
  vbox_->setContentsMargins(0, 0, 0, 0);

  setLayout(vbox_);
  setWindowTitle("PasswordManager");

  /* Connect login signals */

  connect(login_gui_, &LoginGUI::VaultSelected, this, &MainGUI::OnVaultSelected);
  connect(pw_gui_, &PasswordGUI::LoginRequested, this, &MainGUI::OnLoginRequested);
  connect(pw_gui_, &PasswordGUI::BackRequested, this, &MainGUI::OnBackToLogin);

  /* Connect list signals */

  connect(list_gui_, &ListGUI::AddRequested, this, &MainGUI::OnAddRequested);
  connect(list_gui_, &ListGUI::EditRequested, this, &MainGUI::OnEditRequested);
  connect(list_gui_, &ListGUI::DeleteRequested, this, &MainGUI::OnDeleteRequested);
  connect(list_gui_, &ListGUI::CopyPWRequested, this, &MainGUI::OnCopyPWRequested);
  connect(list_gui_, &ListGUI::SaveRequested, this, &MainGUI::OnSaveRequested);
  connect(list_gui_, &ListGUI::CloseRequested, this, &MainGUI::OnCloseRequested);
  connect(list_gui_, &ListGUI::ChangePWRequested, this, &MainGUI::OnChangePWRequested);

  /* Set verify callback for password change */

  change_pw_gui_->SetVerifyCb([this](const Password& pw) -> bool { return vault_.VerifyPW(pw); });
}

MainGUI::~MainGUI() {
  ;
}

void MainGUI::OnVaultSelected(VaultAction action, const QString& path) {
  pw_gui_->SetVaultInfo(action, path);

  stack_->setCurrentWidget(pw_gui_);
}

void MainGUI::OnLoginRequested(const LoginRequest& req) {
  Result res;

  /* Create or open the vault, deriving the session key from the master password */

  if (req.action == VaultAction::kCreate) {
    res = vault_.NewVault(req.path, req.pw);
  }
  else {
    res = vault_.OpenVault(req.path, req.pw);
  }

  if (res == Result::kFailure) {
    pw_gui_->SetErrMsg(vault_.GetLastError());
    return;
  }

  /* Switch to list screen */

  RefreshList();

  stack_->setCurrentWidget(list_gui_);
  resize(300, 300);
}

void MainGUI::OnBackToLogin() {
  stack_->setCurrentWidget(login_gui_);
}

void MainGUI::OnAddRequested() {
  is_edit_mode_ = false;

  entry_gui_->SetAddMode();

  if (entry_gui_->exec() == QDialog::Accepted) {
    EntryInput input = entry_gui_->GetInput();

    if (vault_.CreateEntry(input.site, input.acc, input.pw) == Result::kFailure) {
      list_gui_->SetErrMsg("Entry already exists");
      return;
    }

    RefreshList();
  }
}

void MainGUI::OnEditRequested(const QString& site, const QString& acc) {
  is_edit_mode_ = true;
  orig_site_ = site;
  orig_acc_ = acc;

  /* Find the entry to get its password */

  Password pw;

  if (!vault_.GetPW(site, acc, pw)) {
    list_gui_->SetErrMsg("Entry not found");
    return;
  }

  entry_gui_->SetEditMode(site, acc, pw);

  if (entry_gui_->exec() == QDialog::Accepted) {
    EntryInput input = entry_gui_->GetInput();
    UpdateResult res = vault_.UpdateEntry(orig_site_, orig_acc_, input.site, input.acc, input.pw);

    if (res == UpdateResult::kNotFound) {
      list_gui_->SetErrMsg("Original entry not found");
      return;
    }

    if (res == UpdateResult::kDuplicate) {
      list_gui_->SetErrMsg("Entry already exists");
      return;
    }

    if (res == UpdateResult::kError) {
      list_gui_->SetErrMsg("Failed to update entry");
      return;
    }

    RefreshList();
  }
}

void MainGUI::OnDeleteRequested(const QString& site, const QString& acc) {
  if (vault_.DeleteEntry(site, acc) == Result::kFailure) {
    list_gui_->SetErrMsg("Failed to delete entry");
    return;
  }

  RefreshList();
}

void MainGUI::OnCopyPWRequested(const QString& site, const QString& acc) {
  Password pw;

  if (!vault_.GetPW(site, acc, pw)) {
    list_gui_->SetErrMsg("Entry not found");
    return;
  }

  /* Copy password to clipboard */

  QClipboard* board = QGuiApplication::clipboard();

  board->setText(QString::fromUtf8(pw.GetData(), static_cast<int>(pw.GetSize())));

  /* Auto-clear clipboard after 30 seconds */

  countdown_ = 30;

  list_gui_->SetErrMsg("Password copied (clears after 30s)");

  if (timer_) {
    timer_->stop();
    timer_->disconnect();
  }
  else {
    timer_ = new QTimer(this);
  }

  connect(timer_, &QTimer::timeout, this, [this, board]() {
    countdown_--;

    if (countdown_ > 0) {
      list_gui_->SetErrMsg(QString("Password copied (clears after %1s)").arg(countdown_));
    }
    else {
      timer_->stop();
      board->clear();
      list_gui_->SetErrMsg("Clipboard cleared");
      timer_->deleteLater();
      timer_ = nullptr;
    }
  });

  timer_->setSingleShot(false);
  timer_->start(1000);
}

void MainGUI::OnSaveRequested() {
  if (vault_.SaveVault() == Result::kFailure) {
    list_gui_->SetErrMsg(vault_.GetLastError());
    return;
  }

  list_gui_->SetErrMsg("Saved");
}

void MainGUI::OnCloseRequested() {
  vault_.CloseVault();

  stack_->setCurrentWidget(login_gui_);
  resize(300, 150);
}

void MainGUI::OnChangePWRequested() {
  change_pw_gui_->Reset();

  if (change_pw_gui_->exec() == QDialog::Accepted) {
    Password cur_pw, new_pw;

    change_pw_gui_->GetInput(cur_pw, new_pw);

    /* Deriving the new key and re-encrypting is heavy, so show a busy state */

    list_gui_->SetErrMsg("Changing master password...");
    QApplication::setOverrideCursor(Qt::WaitCursor);
    QApplication::processEvents();

    Result res = vault_.ChangePW(new_pw);

    QApplication::restoreOverrideCursor();

    if (res == Result::kFailure) {
      list_gui_->SetErrMsg("Failed to save vault");
      return;
    }

    list_gui_->SetErrMsg("Password changed");
  }
}

void MainGUI::closeEvent(QCloseEvent* event) {
  if (timer_) {
    timer_->stop();
    timer_->disconnect();
    timer_->deleteLater();
    timer_ = nullptr;

    QClipboard* board = QGuiApplication::clipboard();
    board->clear();
  }

  QWidget::closeEvent(event);
}

void MainGUI::RefreshList() {
  list_gui_->LoadEntries(vault_.GetEntries());
}