/**
 * @file	ListGUI.h
 * @brief	Entry list window with CRUD operations
 * @author	Astatine387
 */

#pragma once

#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QTableWidget>
#include <QVBoxLayout>
#include <QString>
#include <QWidget>
#include <vector>

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
	explicit ListGUI(QWidget *parent = nullptr);

	/**
	 * @brief	Refresh the table with current entry data
	 * @param	entries		List of entries as (site, account) pairs
	 */
	void loadEntries(const std::vector<std::pair<std::string, std::string>> &entries);

	/**
	 * @brief	Display error message
	 * @param	msg		Error message string
	 */
	void setErrMsg(const QString &msg);

signals:
	/**
	 * @brief	Signal when add button is clicked
	 */
	void addRequested();

	/**
	 * @brief	Signal when edit button is clicked
	 * @param	site	Site name of the selected entry
	 * @param	acc		Account of the selected entry
	 */
	void editRequested(const std::string &site, const std::string &acc);

	/**
	 * @brief	Signal when delete button is clicked
	 * @param	site	Site name of the selected entry
	 * @param	acc		Account of the selected entry
	 */
	void deleteRequested(const std::string &site, const std::string &acc);

	/**
	 * @brief	Signal when copy password button is clicked
	 * @param	site	Site name of the selected entry
	 * @param	acc		Account of the selected entry
	 */
	void copyPWRequested(const std::string &site, const std::string &acc);

	/**
	 * @brief	Signal when save button is clicked
	 */
	void saveRequested();

	/** 
	 * @brief	Signal when close button is clicked
	 */
	void closeRequested();

	/**
	 * @brief	Signal when change password button is clicked
	 */
	void changePWRequested();

private slots:
	/**
	 * @brief	Handle add button click
	 */
	void onAddClicked();

	/**
	 * @brief	Handle edit button click
	 */
	void onEditClicked();

	/**
	 * @brief	Handle delete button click
	 */
	void onDeleteClicked();

	/**
	 * @brief	Handle copy password button click
	 */
	void onCopyPWClicked();

	/**
	 * @brief	Filter table rows based on search text
	 * @param	text	Search text
	 */
	void onSearchChanged(const QString &text);

private:
	QLabel *errMsg;
	QLineEdit *searchLine;
	QPushButton *addBtn, *editBtn, *deleteBtn, *copyPWBtn, *saveBtn, *closeBtn, *changePWBtn;
	QTableWidget *table;
	QHBoxLayout *entryBtns, *vaultBtns;
	QVBoxLayout *vBox;

	/**
	 * @brief	Get site and account from the selected row
	 * @param	site	Destination for site name
	 * @param	acc		Destination for account
	 * @return	true if a row is selected
	 */
	bool getSelectedEntry(std::string &site, std::string &acc);
};