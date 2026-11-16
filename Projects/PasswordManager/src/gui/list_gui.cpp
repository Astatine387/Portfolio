/**
 * @file    list_gui.cpp
 * @brief   Implementation of ListGUI class
 * @author  Astatine387
 */

#include "gui/list_gui.h"

#include <QAbstractItemView>
#include <QHeaderView>
#include <QItemSelectionModel>
#include <QModelIndex>
#include <QModelIndexList>

ListGUI::ListGUI(QWidget* parent) : QWidget(parent) {
  /* Create layouts and components */

  err_msg_ = new QLabel();
  model_ = new EntryModel(this);
  proxy_ = new QSortFilterProxyModel(this);
  search_line_ = new QLineEdit;
  add_btn_ = new QPushButton("Add");
  edit_btn_ = new QPushButton("Edit");
  delete_btn_ = new QPushButton("Delete");
  copy_pw_btn_ = new QPushButton("Copy Password");
  save_btn_ = new QPushButton("Save");
  close_btn_ = new QPushButton("Close");
  change_pw_btn_ = new QPushButton("Change Master Password");
  table_ = new QTableView;
  entry_btns_ = new QHBoxLayout;
  vault_btns_ = new QHBoxLayout;
  vbox_ = new QVBoxLayout;

  /* Configure search bar */

  search_line_->setPlaceholderText("Search");

  /* Configure the filter */

  proxy_->setSourceModel(model_);
  proxy_->setFilterKeyColumn(-1);
  proxy_->setFilterCaseSensitivity(Qt::CaseInsensitive);

  /* Configure table */

  table_->setModel(proxy_);

  table_->setSelectionBehavior(QAbstractItemView::SelectRows);
  table_->setSelectionMode(QAbstractItemView::SingleSelection);
  table_->setEditTriggers(QAbstractItemView::NoEditTriggers);

  table_->horizontalHeader()->setStretchLastSection(true);
  table_->verticalHeader()->setVisible(false);

  /* Put add, edit, delete, copy password buttons in the same line */

  entry_btns_->addWidget(add_btn_);
  entry_btns_->addWidget(edit_btn_);
  entry_btns_->addWidget(delete_btn_);
  entry_btns_->addWidget(copy_pw_btn_);
  entry_btns_->addStretch();

  entry_btns_->setSpacing(10);
  entry_btns_->setContentsMargins(0, 0, 0, 0);

  /* Put save, close, change master password buttons in the same line */

  vault_btns_->addWidget(save_btn_);
  vault_btns_->addWidget(close_btn_);
  vault_btns_->addWidget(change_pw_btn_);
  vault_btns_->addStretch();

  vault_btns_->setSpacing(10);
  vault_btns_->setContentsMargins(0, 0, 0, 0);

  /* Configure main layout */

  vbox_->addWidget(search_line_);
  vbox_->addWidget(table_);
  vbox_->addWidget(err_msg_);
  vbox_->addLayout(entry_btns_);
  vbox_->addLayout(vault_btns_);

  vbox_->setSpacing(10);
  vbox_->setContentsMargins(10, 10, 10, 10);

  setLayout(vbox_);

  /* Connect functions to buttons */

  connect(add_btn_, &QPushButton::clicked, this, &ListGUI::OnAddClicked);
  connect(edit_btn_, &QPushButton::clicked, this, &ListGUI::OnEditClicked);
  connect(delete_btn_, &QPushButton::clicked, this, &ListGUI::OnDeleteClicked);
  connect(copy_pw_btn_, &QPushButton::clicked, this, &ListGUI::OnCopyPWClicked);
  connect(save_btn_, &QPushButton::clicked, this, &ListGUI::SaveRequested);
  connect(close_btn_, &QPushButton::clicked, this, &ListGUI::CloseRequested);
  connect(change_pw_btn_, &QPushButton::clicked, this,
          &ListGUI::ChangePWRequested);
  connect(search_line_, &QLineEdit::textChanged, this,
          &ListGUI::OnSearchChanged);
}

void ListGUI::LoadEntries(const QVector<EntryView>& entries) {
  model_->SetEntries(entries);

  err_msg_->clear();
}

void ListGUI::Clear() {
  model_->SetEntries({});

  search_line_->clear();
  err_msg_->clear();
}

void ListGUI::SetErrMsg(const QString& msg) {
  err_msg_->setText(msg);
}

void ListGUI::OnAddClicked() {
  err_msg_->clear();

  emit AddRequested();
}

void ListGUI::OnEditClicked() {
  QString site, acc;

  if (!GetSelectedEntry(site, acc))
    return;

  emit EditRequested(site, acc);
}

void ListGUI::OnDeleteClicked() {
  QString site, acc;

  if (!GetSelectedEntry(site, acc))
    return;

  emit DeleteRequested(site, acc);
}

void ListGUI::OnCopyPWClicked() {
  QString site, acc;

  if (!GetSelectedEntry(site, acc))
    return;

  emit CopyPWRequested(site, acc);
}

void ListGUI::OnSearchChanged(const QString& text) {
  const QModelIndexList selected = table_->selectionModel()->selectedRows();
  const QModelIndex chosen = selected.isEmpty()
                                 ? QModelIndex()
                                 : proxy_->mapToSource(selected.first());

  proxy_->setFilterFixedString(text);

  const QModelIndex kept =
      chosen.isValid() ? proxy_->mapFromSource(chosen) : QModelIndex();

  if (kept.isValid()) {
    table_->selectionModel()->setCurrentIndex(
        kept, QItemSelectionModel::ClearAndSelect | QItemSelectionModel::Rows);
    return;
  }

  table_->selectionModel()->clearSelection();
  table_->selectionModel()->clearCurrentIndex();
}

bool ListGUI::GetSelectedEntry(QString& site, QString& acc) {
  const QModelIndexList selected = table_->selectionModel()->selectedRows();

  if (selected.isEmpty()) {
    err_msg_->setText("No entry selected");
    return false;
  }

  const EntryView* entry =
      model_->EntryAt(proxy_->mapToSource(selected.first()));

  if (entry == nullptr) {
    err_msg_->setText("No entry selected");
    return false;
  }

  err_msg_->clear();

  site = entry->site;
  acc = entry->acc;

  return true;
}
