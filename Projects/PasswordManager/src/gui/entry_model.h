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
 * @class   EntryModel
 * @brief   Read-only table model holding the site and account of every entry
 *
 * The rows are the vault's entries in the order the vault hands them over, and each row keeps the EntryView it was
 * built from. Whatever acts on a row asks the model for that view rather than reading the text back out of the cells,
 * so the identity an operation is carried out under is the one the vault gave, not a round trip through what the
 * table happened to display.
 */
class EntryModel : public QAbstractTableModel {
  Q_OBJECT

 public:
  /**
   * @enum    Column
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
   * The pointer is valid until the next SetEntries call, which is long enough for the caller to copy the fields out
   * of it and no longer.
   */
  [[nodiscard]] const EntryView* EntryAt(const QModelIndex& index) const;

  /* ==================================================
   * QAbstractTableModel interface
   * ================================================== */

  [[nodiscard]] int rowCount(const QModelIndex& parent = QModelIndex()) const override;
  [[nodiscard]] int columnCount(const QModelIndex& parent = QModelIndex()) const override;
  [[nodiscard]] QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
  [[nodiscard]] QVariant headerData(int section, Qt::Orientation ori, int role = Qt::DisplayRole) const override;

 private:
  QVector<EntryView> entries_;
};
