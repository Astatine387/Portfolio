/**
 * @file	MainGUI.cpp
 * @brief	Implementation of MainGUI class
 * @author	Astatine387
 */

#include "GUI/MainGUI.h"

#include <QClipboard>
#include <QGuiApplication>

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

  /* Set error callback */

  vault_.SetErrorCallback([this](const char* msg) { last_error_ = msg; });

  /* Set verify callback for password change */

  change_pw_gui_->SetVerifyCb(
      [this](const Password& curPW) -> bool { return vault_.VerifyPW(curPW); });
}

MainGUI::~MainGUI() {
  ;
}

void MainGUI::OnVaultSelected(int mode, const QString& path) {
  pw_gui_->SetVaultInfo(mode, path);

  stack_->setCurrentWidget(pw_gui_);
}

void MainGUI::OnLoginRequested(const LoginInput& input) {
  int res;

  /* Set master password */

  Password pw;
  pw.SetData(input.pw);
  vault_.SetPW(pw);

  /* Create or open vault */

  if (input.mode == 0) {
    res = vault_.NewVault(input.path);
  }
  else {
    res = vault_.OpenVault(input.path);
  }

  if (res) {
    pw_gui_->SetErrMsg(QString::fromStdString(last_error_));
    return;
  }

  /* Switch to list screen */

  vault_path_ = input.path;

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
    Entry entry = entry_gui_->GetInput();

    if (vault_.CreateEntry(entry.site, entry.acc, entry.pw)) {
      list_gui_->SetErrMsg("Entry already exists");
      return;
    }

    RefreshList();
  }
}

void MainGUI::OnEditRequested(const std::string& site, const std::string& acc) {
  is_edit_mode_ = true;
  orig_site_ = site;
  orig_acc_ = acc;

  /* Find the entry to get its password */

  Entry target = { site, acc };
  const auto& entries = vault_.GetEntries();
  auto it = entries.find(target);

  if (it == entries.end()) {
    list_gui_->SetErrMsg("Entry not found");
    return;
  }

  entry_gui_->SetEditMode(site, acc, it->pw);

  if (entry_gui_->exec() == QDialog::Accepted) {
    Entry entry = entry_gui_->GetInput();
    int res = vault_.UpdateEntry(orig_site_, orig_acc_, entry.site, entry.acc, entry.pw);

    if (res == 1) {
      list_gui_->SetErrMsg("Original entry not found");
      return;
    }

    if (res == 2) {
      list_gui_->SetErrMsg("Entry already exists");
      return;
    }

    RefreshList();
  }
}

void MainGUI::OnDeleteRequested(const std::string& site, const std::string& acc) {
  if (vault_.DeleteEntry(site, acc)) {
    list_gui_->SetErrMsg("Failed to delete entry");
    return;
  }

  RefreshList();
}

void MainGUI::OnCopyPWRequested(const std::string& site, const std::string& acc) {
  Entry target = { site, acc };
  const auto& entries = vault_.GetEntries();
  auto it = entries.find(target);

  if (it == entries.end()) {
    list_gui_->SetErrMsg("Entry not found");
    return;
  }

  /* Copy password to clipboard */

  QClipboard* board = QGuiApplication::clipboard();

  board->setText(QString::fromUtf8(it->pw.GetData(), static_cast<int>(it->pw.GetSize())));

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
  if (vault_.SaveVault(vault_path_)) {
    pw_gui_->SetErrMsg(QString::fromStdString(last_error_));
    return;
  }

  list_gui_->SetErrMsg("Saved");
}

void MainGUI::OnCloseRequested() {
  vault_.CloseVault();
  vault_path_.clear();

  stack_->setCurrentWidget(login_gui_);
  resize(300, 150);
}

void MainGUI::OnChangePWRequested() {
  change_pw_gui_->Reset();

  if (change_pw_gui_->exec() == QDialog::Accepted) {
    Password curPW, newPW;

    change_pw_gui_->GetInput(curPW, newPW);

    if (vault_.ChangePW(newPW, vault_path_)) {
      list_gui_->SetErrMsg("Failed to save vault");
      return;
    }

    list_gui_->SetErrMsg("Password changed");
  }
}

void MainGUI::CloseEvent(QCloseEvent* event) {
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
  std::vector<std::pair<std::string, std::string>> entryVec;
  const auto& entrySet = vault_.GetEntries();

  for (auto it = entrySet.begin(); it != entrySet.end(); it++)
    entryVec.emplace_back(it->site, it->acc);

  list_gui_->LoadEntries(entryVec);
}