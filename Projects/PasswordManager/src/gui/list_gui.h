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
#include <QString>
#include <QTableWidget>
#include <QVBoxLayout>
#include <QWidget>

#include "gui/entry_interface.h"

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
  QLabel* err_msg_;
  QLineEdit* search_line_;
  QPushButton* add_btn_;
  QPushButton* edit_btn_;
  QPushButton* delete_btn_;
  QPushButton* copy_pw_btn_;
  QPushButton* save_btn_;
  QPushButton* close_btn_;
  QPushButton* change_pw_btn_;
  QTableWidget* table_;
  QHBoxLayout* entry_btns_;
  QHBoxLayout* vault_btns_;
  QVBoxLayout* vbox_;

  /**
   * @brief	Get site and account from the selected row
   * @param	site	Destination for site name
   * @param	acc		Destination for account
   * @return	true if a row is selected
   */
  bool GetSelectedEntry(QString& site, QString& acc);
};