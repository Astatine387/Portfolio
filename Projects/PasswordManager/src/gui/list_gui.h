/**
 * @file	list_gui.h
 * @brief	Entry list window with CRUD operations
 * @author	Astatine387
 */

#pragma once

#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QSortFilterProxyModel>
#include <QString>
#include <QTableView>
#include <QVBoxLayout>
#include <QWidget>

#include "gui/entry_interface.h"
#include "gui/entry_model.h"

/**
 * @class	ListGUI
 * @brief	Entry list window with CRUD operations
 */
class ListGUI : public QWidget {
  Q_OBJECT

 public:
  /**
   * @brief	Constructor of ListGUI class
   * @param	parent	Parent widget
   */
  explicit ListGUI(QWidget* parent = nullptr);

  /**
   * @brief	Refresh the table with current entry data
   * @param	entries		List of entries
   */
  void LoadEntries(const QVector<EntryView>& entries);

  /**
   * @brief	Display error message
   * @param	msg		Error message string
   */
  void SetErrMsg(const QString& msg);

  /**
   * @brief	Drop every row, the search text and the message, so nothing of a closed vault stays in the widget
   */
  void Clear();

 signals:
  /**
   * @brief	Signal when add button is clicked
   */
  void AddRequested();

  /**
   * @brief	Signal when edit button is clicked
   * @param	site	Site name of the selected entry
   * @param	acc		Account of the selected entry
   */
  void EditRequested(const QString& site, const QString& acc);

  /**
   * @brief	Signal when delete button is clicked
   * @param	site	Site name of the selected entry
   * @param	acc		Account of the selected entry
   */
  void DeleteRequested(const QString& site, const QString& acc);

  /**
   * @brief	Signal when copy password button is clicked
   * @param	site	Site name of the selected entry
   * @param	acc		Account of the selected entry
   */
  void CopyPWRequested(const QString& site, const QString& acc);

  /**
   * @brief	Signal when save button is clicked
   */
  void SaveRequested();

  /**
   * @brief	Signal when close button is clicked
   */
  void CloseRequested();

  /**
   * @brief	Signal when change password button is clicked
   */
  void ChangePWRequested();

 private slots:
  /**
   * @brief	Handle add button click
   */
  void OnAddClicked();

  /**
   * @brief	Handle edit button click
   */
  void OnEditClicked();

  /**
   * @brief	Handle delete button click
   */
  void OnDeleteClicked();

  /**
   * @brief	Handle copy password button click
   */
  void OnCopyPWClicked();

  /**
   * @brief	Filter table rows based on search text
   * @param	text	Search text
   */
  void OnSearchChanged(const QString& text);

 private:
  EntryModel* model_;
  QSortFilterProxyModel* proxy_;
  QLabel* err_msg_;
  QLineEdit* search_line_;
  QPushButton* add_btn_;
  QPushButton* edit_btn_;
  QPushButton* delete_btn_;
  QPushButton* copy_pw_btn_;
  QPushButton* save_btn_;
  QPushButton* close_btn_;
  QPushButton* change_pw_btn_;
  QTableView* table_;
  QHBoxLayout* entry_btns_;
  QHBoxLayout* vault_btns_;
  QVBoxLayout* vbox_;

  /**
   * @brief	Get site and account of the selected entry
   * @param	site	Destination for site name
   * @param	acc		Destination for account
   * @return	true if an entry is selected
   *
   * The search line filters through the proxy model, so a row the filter leaves out is not in the view at all and
   * cannot be selected or current. What this returns is therefore always an entry the user is looking at, and it is
   * read from the model rather than from the text of the cells.
   */
  bool GetSelectedEntry(QString& site, QString& acc);
};
