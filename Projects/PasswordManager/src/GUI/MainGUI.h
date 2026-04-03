/**
 * @file	MainGUI.h
 * @brief	Main GUI class that controls entire workflow
 * @author	Astatine387
 */

#pragma once

#include "Core/Vault.h"
#include "GUI/ChangePWGUI.h"
#include "GUI/EntryGUI.h"
#include "GUI/ListGUI.h"
#include "GUI/LoginGUI.h"
#include "GUI/PasswordGUI.h"

#include <QStackedWidget>
#include <QString>
#include <QTimer>
#include <QVBoxLayout>
#include <QWidget>
#include <string>

/**
 * @class	MainGUI
 * @brief	Main GUI class that orchestrates entire workflow
 */
class MainGUI : public QWidget {
	Q_OBJECT

public:
	/**
	 * @brief	Constructor of MainGUI class
	 * @param	parent	Parent widget
	 */
	explicit MainGUI(QWidget *parent = nullptr);

	/**
	 * @brief	Destructor of MainGUI class
	 */
	~MainGUI();


	/* ==================================================
	 * Callback functions
	 * ================================================== */

	/**
	 * @brief	Callback function for error reporting
	 * @param	errMsg	Error message string
	 */
	using ErrorCallback = std::function<void(const char *errMsg)>;

	/**
	 * @brief	Set error callback function
	 * @param	ecb		Error callback function
	 */
	void setErrorCb(ErrorCallback ecb) {
		this->ecb = ecb;
	}

private slots:
	/**
	 * @brief	Switch to password input screen
	 * @param	mode	0 for new, 1 for open
	 * @param	path	Vault file path
	 */
	void onVaultSelected(int mode, const QString &path);

	/**
	 * @brief	Process vault login request
	 * @param	input	Login input parameters
	 */
	void onLoginRequested(const LoginInput &input);

	/**
	 * @brief	Return to login screen
	 */
	void onBackToLogin();

	/**
	 * @brief	Process entry add request
	 */
	void onAddRequested();

	/**
	 * @brief	Process entry edit request
	 * @param	site	Site of entry to be edited
	 * @param	acc		Account of entry to be edited
	 */
	void onEditRequested(const std::string &site, const std::string &acc);

	/**
	 * @brief	Process entry delete request
	 * @param	site	Site of entry to be deleted
	 * @param	acc		Account of entry to be deleted
	 */
	void onDeleteRequested(const std::string &site, const std::string &acc);

	/**
	 * @brief	Process copy password request
	 * @param	site	Site of entry to copy password from
	 * @param	acc		Account of entry to copy password from
	 */
	void onCopyPWRequested(const std::string &site, const std::string &acc);

	/**
	 * @brief	Process vault save request
	 */
	void onSaveRequested();

	/** 
	 * @brief	Process vault close request
	 */
	void onCloseRequested();

	/**
	 * @brief	Process change master password request
	 */
	void onChangePWRequested();

private:
	ChangePWGUI *changePWGUI;
	EntryGUI *entryGUI;
	ListGUI *listGUI;
	LoginGUI *loginGUI;
	PasswordGUI *pwGUI;
	QStackedWidget *stack;
	QString vaultPath;
	QTimer *timer = nullptr;
	QVBoxLayout *vBox;
	Vault vault;

	int countdown = 0;

	std::string lastError;
	std::string origSite;
	std::string origAcc;
	bool isEditMode = false;

	ErrorCallback ecb = nullptr;

	/**
	 * @brief	Clean timer and clipboard when GUI is closed
	 */
	void closeEvent(QCloseEvent *event);

	/**
	 * @brief	Refresh list GUI
	 */
	void refreshList();
};