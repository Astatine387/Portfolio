/**
 * @file	ChangePWGUI.h
 * @brief	Master password change GUI
 * @author	Astatine387
 */

#pragma once

#include "GUI/PWLineEdit.h"
#include "Utils/Password.h"
#include <QDialog>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QString>
#include <QVBoxLayout>
#include <QWidget>

/**
 * @class	ChangePWGUI
 * @brief	Dialog for changing the master password
 */
class ChangePWGUI : public QDialog {
	Q_OBJECT

public:
	/**
	 * @brief	Constructor of ChangePWGUI class
	 * @param	parent	Parent widget
	 */
	explicit ChangePWGUI(QWidget *parent = nullptr);

	/**
	 * @brief	Get the change password input from the dialog
	 * @return	Change password input parameters
	 */
	void getInput(Password &curPw, Password &newPw);

	/**
	 * @brief	Reset all input fields
	 */
	void reset();

	/**
	 * @brief	Display error message
	 * @param	msg		Error message string
	 */
	void setErrMsg(const QString &msg);


	/* ==================================================
	 * Callback functions
	 * ================================================== */

	/**
	 * @brief	Callback function for verifying current password
	 * @param	curPW	Current password to verify
	 * @return	true if password is correct
	 */
	using VerifyCallback = std::function<bool(const Password &curPW)>;

	/**
	 * @brief	Set verify callback function
	 * @param	vcb		Verify callback function
	 */
	void setVerifyCb(VerifyCallback vcb);

private slots:
	/**
	 * @brief	Validate input and accept dialog
	 */
	void onOKClicked();

private:
	PWLineEdit *curPWLine, *newPWLine, *confirmPWLine;
	QLabel *curLabel, *newLabel, *confirmLabel, *errMsg;
	QPushButton *okBtn, *cancelBtn;
	QHBoxLayout *btnBox;
	QVBoxLayout *vBox;

	VerifyCallback vcb = nullptr;
};