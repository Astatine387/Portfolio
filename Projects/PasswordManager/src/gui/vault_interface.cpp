/**
 * @file	vault_interface.cpp
 * @brief	implementation of VaultInterface class
 * @author	Astatine387
 */

#include "gui/vault_interface.h"

VaultInterface::VaultInterface() : vault_(std::make_unique<Vault>()) {
  vault_->SetErrorCallback([this](const char* msg) { last_error_ = QString::fromUtf8(msg); });
}

Result VaultInterface::NewVault(const QString& path, const Password& pw) {
  vault_path_ = path;
  return vault_->NewVault(path.toStdString(), pw);
}

Result VaultInterface::OpenVault(const QString& path, const Password& pw) {
  vault_path_ = path;
  return vault_->OpenVault(path.toStdString(), pw);
}

Result VaultInterface::SaveVault() {
  return vault_->SaveVault(vault_path_.toStdString());
}

void VaultInterface::CloseVault() {
  vault_->CloseVault();
  vault_path_.clear();
}

bool VaultInterface::VerifyPW(const Password& pw) const {
  return vault_->VerifyPW(pw);
}

Result VaultInterface::ChangePW(const Password& pw) {
  return vault_->ChangePW(pw, vault_path_.toStdString());
}

Result VaultInterface::CreateEntry(const QString& site, const QString& acc, const Password& pw) {
  return vault_->CreateEntry(site.toStdString(), acc.toStdString(), pw);
}

UpdateResult VaultInterface::UpdateEntry(const QString& old_site, const QString& old_acc, const QString& new_site,
                                         const QString& new_acc, const Password& new_pw) {
  return vault_->UpdateEntry(old_site.toStdString(), old_acc.toStdString(), new_site.toStdString(),
                             new_acc.toStdString(), new_pw);
}

Result VaultInterface::DeleteEntry(const QString& site, const QString& acc) {
  return vault_->DeleteEntry(site.toStdString(), acc.toStdString());
}

QVector<EntryView> VaultInterface::GetEntries() const {
  QVector<EntryView> views;
  const auto& entries = vault_->GetEntries();

  for (const auto& entry : entries) {
    views.append({ .site = QString::fromStdString(entry.site), .acc = QString::fromStdString(entry.acc) });
  }

  return views;
}

bool VaultInterface::GetPW(const QString& site, const QString& acc, Password& pw) const {
  return vault_->GetEntryPW(site.toStdString(), acc.toStdString(), pw);
}

QString VaultInterface::GetLastError() const {
  return last_error_;
}
