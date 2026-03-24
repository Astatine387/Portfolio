/**
 * @file	PasswordGUI.h
 * @brief	Password input window for vault authentication
 * @author	Astatine387
 */

#pragma once

#include "GUI/PWLineEdit.h"
#include "Utils/Password.h"
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QString>
#include <QVBoxLayout>
#include <QWidget>

/**
 * @struct	LoginInput
 * @brief	Container for login input parameters
 */
struct LoginInput {
	int mode = -1;	// 0: new, 1: open
	QString path;
	Password pw;
};

/**
 * @class	PasswordGUI
 * @brief	Password input window for vault authentication
 */
class PasswordGUI : public QWidget {
	Q_OBJECT

public:
	/**
	 * @brief	Constructor of PasswordGUI class
	 * @param	parent	Parent widget
	 */
	explicit PasswordGUI(QWidget *parent = nullptr);

	/**
	 * @brief	Set vault mode and path from LoginGUI
	 * @param	mode	0 for new, 1 for open
	 * @param	path	Vault file path
	 */
	void setVaultInfo(int mode, const QString &path);

	/**
	 * @brief	Display error message
	 * @param	msg		Error message string
	 */
	void setErrMsg(const QString &msg);

signals:
	/**
	 * @brief	Signal when login is confirmed
	 * @param	input	Login input parameters
	 */
	void loginRequested(const LoginInput &input);

	/**
	 * @brief	Signal when back button is clicked
	 */
	void backRequested();

private slots:
	/**
	 * @brief	Validate input and emit login request
	 */
	void onConfirmClicked();

private:
	PWLineEdit *pwLine;
	QLabel *pathLabel;
	QLabel *errMsg;
	QPushButton *backBtn;
	QPushButton *confirmBtn;
	QString path;
	QHBoxLayout *btnBox;
	QVBoxLayout *vBox;

	int mode = -1;
};