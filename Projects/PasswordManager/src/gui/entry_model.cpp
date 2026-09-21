/**
 * @file    entry_model.cpp
 * @brief   Implementation of EntryModel class
 * @author  Astatine387
 */

#include "gui/entry_model.h"

EntryModel::EntryModel(QObject* parent) : QAbstractTableModel(parent) {
  ;
}

void EntryModel::SetEntries(const QVector<EntryView>& entries) {
  /* A reset rather than a diff: the list is rebuilt from the vault after every edit, and a reset is what tells every
   * view and every selection model above this one that the rows they were holding are gone. */

  beginResetModel();

  entries_ = entries;

  endResetModel();
}

const EntryView* EntryModel::EntryAt(const QModelIndex& index) const {
  if (!index.isValid() || index.model() != this) {
    return nullptr;
  }

  if (index.row() < 0 || index.row() >= entries_.size()) {
    return nullptr;
  }

  return &entries_.at(index.row());
}

int EntryModel::rowCount(const QModelIndex& parent) const {
  /* A table model has rows under the root and nowhere else */

  return parent.isValid() ? 0 : static_cast<int>(entries_.size());
}

int EntryModel::columnCount(const QModelIndex& parent) const {
  return parent.isValid() ? 0 : kColumnCount;
}

QVariant EntryModel::data(const QModelIndex& index, int role) const {
  const EntryView* entry = EntryAt(index);

  if (entry == nullptr || role != Qt::DisplayRole) {
    return {};
  }

  if (index.column() == kSite) {
    return entry->site;
  }

  if (index.column() == kAccount) {
    return entry->acc;
  }

  return {};
}

QVariant EntryModel::headerData(int section, Qt::Orientation ori, int role) const {
  if (ori != Qt::Horizontal || role != Qt::DisplayRole) {
    return {};
  }

  if (section == kSite) {
    return QString("Site");
  }

  if (section == kAccount) {
    return QString("Account");
  }

  return {};
}
