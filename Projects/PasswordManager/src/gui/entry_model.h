/**
 * @file    entry_model.h
 * @brief   Table model over the entry list shown by ListGUI
 * @author  Astatine387
 */

#pragma once

#include <QAbstractTableModel>
#include <QModelIndex>
#include <QObject>
#include <QVariant>
#include <QVector>
#include <cstdint>

#include "gui/entry_interface.h"

/**
 * @brief   Read-only table model holding the site and account of every entry
 */
class EntryModel : public QAbstractTableModel {
  Q_OBJECT

 public:
  /**
   * @brief   Columns of the table, in the order they are shown
   */
  enum Column : std::uint8_t {
    kSite = 0,
    kAccount = 1,
    kColumnCount = 2,
  };

  /**
   * @brief   Constructor of EntryModel class
   * @param   parent  Parent object
   */
  explicit EntryModel(QObject* parent = nullptr);

  /**
   * @brief   Replace every row with the given entries
   * @param   entries   Entries to show
   */
  void SetEntries(const QVector<EntryView>& entries);

  /**
   * @brief   Return the entry a source index refers to
   * @param   index   Index into this model
   * @return  Pointer to the entry, or nullptr when the index does not name one
   *
   * The pointer is valid until the next SetEntries call, which is long enough
   * for the caller to copy the fields out of it and no longer.
   */
  [[nodiscard]] const EntryView* EntryAt(const QModelIndex& index) const;

  /* ==================================================
   * QAbstractTableModel interface
   * ================================================== */

  [[nodiscard]] int rowCount(
      const QModelIndex& parent = QModelIndex()) const override;
  [[nodiscard]] int columnCount(
      const QModelIndex& parent = QModelIndex()) const override;
  [[nodiscard]] QVariant data(const QModelIndex& index,
                              int role = Qt::DisplayRole) const override;
  [[nodiscard]] QVariant headerData(int section, Qt::Orientation ori,
                                    int role = Qt::DisplayRole) const override;

 private:
  QVector<EntryView> entries_;
};
