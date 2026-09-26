/**
 * @file	main_gui.cpp
 * @brief	Implementation of MainGUI class
 * @author	Astatine387
 */

#include "gui/main_gui.h"

#include <QApplication>
#include <QCloseEvent>
#include <QGuiApplication>
#include <QMessageBox>
#include <QPushButton>

#include "gui/clipboard.h"
#include "gui/entry_interface.h"

namespace {

/**
 * @brief   State ahead of a message that the publish it reports replaced another program's changes
 * @param   msg   Message the same publish would have shown had nothing else touched the file
 * @return  That message with the overwrite stated in front of it
 *
 * Joined the way a warning is joined to what it qualifies, so the two read as one line. It goes in front rather than
 * behind because the message it qualifies may itself be the core's warning, which ends in a newline and has nothing
 * that can follow it, and because replacing somebody else's work is the larger of the two things to say.
 */
QString NoteOverwrite(const QString& msg) {
  return "Overwrote changes made elsewhere. " + msg;
}

}  // namespace

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
  entry_gui_->SetAddMode();

  if (entry_gui_->exec() == QDialog::Accepted) {
    EntryInput input = entry_gui_->GetInput();

    if (vault_.CreateEntry(input.site, input.acc, input.pw) == Result::kFailure) {
      list_gui_->SetErrMsg(vault_.GetLastError());
      return;
    }

    RefreshList();
  }
}

void MainGUI::OnEditRequested(const QString& site, const QString& acc) {
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
      list_gui_->SetErrMsg(vault_.GetLastError());
      return;
    }

    RefreshList();
  }
}

void MainGUI::OnDeleteRequested(const QString& site, const QString& acc) {
  QMessageBox box(this);

  box.setIcon(QMessageBox::Warning);
  box.setWindowTitle("Delete Entry");

  /* Plain text because the site and the account are the user's own, and the default format would read tags in them
   * as markup. One arg() call with both, so a "%2" in the site is not replaced with the account. */

  box.setTextFormat(Qt::PlainText);
  box.setText(QString("Delete the entry for %1 (%2)?").arg(site, acc));
  box.setInformativeText("This cannot be undone once the vault is saved.");

  /* Cancel is the default and the escape button both, so Enter, Escape and the title bar all keep the entry */

  const QPushButton* del = box.addButton("Delete", QMessageBox::DestructiveRole);
  QPushButton* cancel = box.addButton(QMessageBox::Cancel);

  box.setDefaultButton(cancel);
  box.setEscapeButton(cancel);

  box.exec();

  if (box.clickedButton() != del) {
    return;
  }

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

  /* Copy password to clipboard, excluded from OS history and cloud sync */

  clipboard::SetSecret(pw);

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

  connect(timer_, &QTimer::timeout, this, [this]() {
    countdown_--;

    if (countdown_ > 0) {
      list_gui_->SetErrMsg(QString("Password copied (clears after %1s)").arg(countdown_));
    }
    else {
      timer_->stop();

      /* Only clear if we still own the clipboard */

      if (clipboard::ClearIfOwned()) {
        list_gui_->SetErrMsg("Clipboard cleared");
      }
      else {
        list_gui_->SetErrMsg("Clipboard already replaced");
      }

      timer_->deleteLater();
      timer_ = nullptr;
    }
  });

  timer_->setSingleShot(false);
  timer_->start(1000);
}

void MainGUI::OnSaveRequested() {
  const SaveResult outcome = SaveWithConflictPrompt([this](SaveMode mode) { return vault_.SaveVault(mode); });

  if (outcome == SaveResult::kError) {
    list_gui_->SetErrMsg(vault_.GetLastError());
    return;
  }

  if (outcome == SaveResult::kCancelled) {
    list_gui_->SetErrMsg("Not saved - the vault file changed on disk and was left as it is");
    return;
  }

  const QString warning = vault_.GetLastWarning();
  const QString msg = warning.isEmpty() ? QString("Saved") : warning;

  list_gui_->SetErrMsg(outcome == SaveResult::kOverwrote ? NoteOverwrite(msg) : msg);
}

void MainGUI::OnCloseRequested() {
  if (!ConfirmDiscard()) {
    return;
  }

  StopClipboardCountdown();

  vault_.CloseVault();

  /* The widgets are built once and outlive every session, so what the session left in them goes with it. SetAddMode
   * empties the edit dialog's site, account and password lines, and the entry it was editing stops being a thing
   * this screen remembers. */

  list_gui_->Clear();
  entry_gui_->SetAddMode();

  orig_site_.clear();
  orig_acc_.clear();

  stack_->setCurrentWidget(login_gui_);
  resize(300, 150);
}

void MainGUI::OnChangePWRequested() {
  change_pw_gui_->Reset();

  if (change_pw_gui_->exec() == QDialog::Accepted) {
    Password cur_pw, new_pw;

    change_pw_gui_->GetInput(cur_pw, new_pw);

    /* The busy state wraps the change itself and nothing else. A conflict prompt is asked between two of these
     * calls, and a wait cursor left standing over a dialog tells the user to wait for something that is waiting for
     * them. */

    const SaveResult outcome = SaveWithConflictPrompt([this, &new_pw](SaveMode mode) {
      list_gui_->SetErrMsg("Changing master password...");
      QApplication::setOverrideCursor(Qt::WaitCursor);
      QApplication::processEvents();

      const ::SaveResult res = vault_.ChangePW(new_pw, mode);

      QApplication::restoreOverrideCursor();

      return res;
    });

    if (outcome == SaveResult::kError) {
      list_gui_->SetErrMsg(vault_.GetLastError());
      return;
    }

    if (outcome == SaveResult::kCancelled) {
      list_gui_->SetErrMsg("Master password not changed - the vault file changed on disk and was left as it is");
      return;
    }

    const QString warning = vault_.GetLastWarning();
    const QString msg = warning.isEmpty() ? QString("Password changed") : "Password changed. " + warning;

    list_gui_->SetErrMsg(outcome == SaveResult::kOverwrote ? NoteOverwrite(msg) : msg);
  }
}

void MainGUI::closeEvent(QCloseEvent* event) {
  /* Asked before anything is torn down, so a cancelled close leaves the clipboard countdown running as it was */

  if (!ConfirmDiscard()) {
    event->ignore();
    return;
  }

  StopClipboardCountdown();

  QWidget::closeEvent(event);
}

void MainGUI::RefreshList() {
  list_gui_->LoadEntries(vault_.GetEntries());
}

bool MainGUI::ConfirmDiscard() {
  if (!vault_.IsDirty()) {
    return true;
  }

  /* Save is the default so that Enter keeps the changes; Escape and the title bar close map to Cancel */

  const QMessageBox::StandardButton choice = QMessageBox::warning(
      this, "Unsaved Changes", "The vault has changes that have not been saved.\nSave them before closing?",
      QMessageBox::Save | QMessageBox::Discard | QMessageBox::Cancel, QMessageBox::Save);

  if (choice == QMessageBox::Save) {
    const SaveResult outcome = SaveWithConflictPrompt([this](SaveMode mode) { return vault_.SaveVault(mode); });

    /* Refusing to overwrite is an answer rather than a failure, but it leaves the changes exactly where a failure
     * does: unsaved, and not to be dropped. So the close is called off either way, and the two differ only in what
     * the line says about why. */

    if (outcome == SaveResult::kError) {
      list_gui_->SetErrMsg(vault_.GetLastError());
      return false;
    }

    if (outcome == SaveResult::kCancelled) {
      list_gui_->SetErrMsg("Not saved - the vault file changed on disk and was left as it is");
      return false;
    }

    return true;
  }

  return choice == QMessageBox::Discard;
}

MainGUI::SaveResult MainGUI::SaveWithConflictPrompt(const std::function<::SaveResult(SaveMode)>& op) {
  ::SaveResult res = op(SaveMode::kRefuseChanged);

  if (res == ::SaveResult::kSuccess) {
    return SaveResult::kSaved;
  }

  while (res == ::SaveResult::kConflict) {
    if (!ConfirmOverwrite()) {
      return SaveResult::kCancelled;
    }

    res = op(SaveMode::kOverwriteAcknowledged);

    if (res == ::SaveResult::kSuccess) {
      return SaveResult::kOverwrote;
    }
  }

  return SaveResult::kError;
}

bool MainGUI::ConfirmOverwrite() {
  QMessageBox box(this);

  box.setIcon(QMessageBox::Warning);
  box.setWindowTitle("Vault Changed on Disk");
  box.setText(
      "The vault file on disk is no longer the one this window opened or last saved. Another window or program may "
      "have changed, replaced or deleted it.");
  box.setInformativeText(
      "Overwriting replaces those changes with this window's version, including a master password change if one was "
      "made there. This cannot be undone.");

  /* Added rather than taken from the standard set, so the destructive answer says what it does and is marked as
   * destructive. Cancel is the default and the escape button both, which is what keeps Enter and Escape - the two
   * keys a dialog gets dismissed with without being read - off the overwrite. */

  const QPushButton* overwrite = box.addButton("Overwrite", QMessageBox::DestructiveRole);
  QPushButton* cancel = box.addButton(QMessageBox::Cancel);

  box.setDefaultButton(cancel);
  box.setEscapeButton(cancel);

  box.exec();

  return box.clickedButton() == overwrite;
}

void MainGUI::StopClipboardCountdown() {
  if (!timer_) {
    return;
  }

  timer_->stop();
  timer_->disconnect();
  timer_->deleteLater();
  timer_ = nullptr;

  /* Only clear if we still own the clipboard */

  clipboard::ClearIfOwned();
}
