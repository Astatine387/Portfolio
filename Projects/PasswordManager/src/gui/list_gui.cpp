/**
 * @file	list_gui.cpp
 * @brief	Implementation of ListGUI class
 * @author	Astatine387
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

  /* Configure the filter. The search line matches against every column, and as a fixed string rather than a pattern,
   * so a user typing a bracket or a dot searches for that character instead of writing a regular expression. */

  proxy_->setSourceModel(model_);
  proxy_->setFilterKeyColumn(-1);
  proxy_->setFilterCaseSensitivity(Qt::CaseInsensitive);

  /* Configure table. The view is given the proxy, so what it shows is what passed the filter: a row the filter turns
   * away has no index in the view and cannot be selected, be current, or be reached by the keyboard. */

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
  connect(change_pw_btn_, &QPushButton::clicked, this, &ListGUI::ChangePWRequested);
  connect(search_line_, &QLineEdit::textChanged, this, &ListGUI::OnSearchChanged);
}

void ListGUI::LoadEntries(const QVector<EntryView>& entries) {
  /* The filter lives in the proxy and survives the rows it was filtering, so a refresh has nothing to re-apply. The
   * reset drops the selection along with the rows it belonged to. */

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
  /* Filtering is a change of which rows exist, not of which rows are painted, so a row that stops matching leaves the
   * view entirely and no operation can be left pointing at an entry the user cannot see.
   *
   * What the entry the user chose becomes is decided here rather than left to Qt. A view in single selection mode
   * answers rows being removed by selecting the next row still present, which would hand the next operation an entry
   * nobody picked, so the choice is carried over when it survives the filter and dropped when it does not. */

  const QModelIndexList selected = table_->selectionModel()->selectedRows();
  const QModelIndex chosen = selected.isEmpty() ? QModelIndex() : proxy_->mapToSource(selected.first());

  proxy_->setFilterFixedString(text);

  const QModelIndex kept = chosen.isValid() ? proxy_->mapFromSource(chosen) : QModelIndex();

  if (kept.isValid()) {
    table_->selectionModel()->setCurrentIndex(kept, QItemSelectionModel::ClearAndSelect | QItemSelectionModel::Rows);
    return;
  }

  table_->selectionModel()->clearSelection();
  table_->selectionModel()->clearCurrentIndex();
}

bool ListGUI::GetSelectedEntry(QString& site, QString& acc) {
  /* The selection rather than the current cell. The two are separate pieces of state in Qt: clearing the selection or
   * Ctrl-clicking the selected row leaves the current cell where it was, and an operation reading the current cell
   * would act on a row that is no longer highlighted. */

  const QModelIndexList selected = table_->selectionModel()->selectedRows();

  if (selected.isEmpty()) {
    err_msg_->setText("No entry selected");
    return false;
  }

  /* Through the proxy to the row the model holds, and out of the model rather than out of the cells */

  const EntryView* entry = model_->EntryAt(proxy_->mapToSource(selected.first()));

  if (entry == nullptr) {
    err_msg_->setText("No entry selected");
    return false;
  }

  err_msg_->clear();

  site = entry->site;
  acc = entry->acc;

  return true;
}
