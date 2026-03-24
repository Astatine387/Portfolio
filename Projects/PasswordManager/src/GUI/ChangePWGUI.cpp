/**
 * @file	ChangePWGUI.cpp
 * @brief	Implementation of ChangePWGUI class
 * @author	Astatine387
 */

#include "GUI/ChangePWGUI.h"

ChangePWGUI::ChangePWGUI(QWidget *parent) : QDialog(parent) {
	/* Create layouts and components */

	curPWLine = new PWLineEdit;
	newPWLine = new PWLineEdit;
	confirmPWLine = new PWLineEdit;
	curLabel = new QLabel("Current Password:");
	newLabel = new QLabel("New Password:");
	confirmLabel = new QLabel("Confirm New Password:");
	errMsg = new QLabel;
	okBtn = new QPushButton("Ok");
	cancelBtn = new QPushButton("Cancel");
	btnBox = new QHBoxLayout;
	vBox = new QVBoxLayout;


	/* Configure error message */

	errMsg->setStyleSheet("color: red;");


	/* Configure button layout */

	btnBox->addStretch();
	btnBox->addWidget(okBtn);
	btnBox->addWidget(cancelBtn);


	/* Configure main layout */

	vBox->addWidget(curLabel);
	vBox->addWidget(curPWLine);
	vBox->addWidget(newLabel);
	vBox->addWidget(newPWLine);
	vBox->addWidget(confirmLabel);
	vBox->addWidget(confirmPWLine);
	vBox->addWidget(errMsg);
	vBox->addLayout(btnBox);
	vBox->setSpacing(10);
	vBox->setContentsMargins(20, 20, 20, 20);

	setLayout(vBox);
	setWindowTitle("Change Master Password");
	setMinimumWidth(400);


	/* Connect functions to buttons */

	connect(okBtn, &QPushButton::clicked, this, &ChangePWGUI::onOKClicked);
	connect(cancelBtn, &QPushButton::clicked, this, &QDialog::reject);
}

void ChangePWGUI::getInput(Password &curPW, Password &newPW) {
	curPWLine->extract(curPW);
	newPWLine->extract(newPW);
}

void ChangePWGUI::reset() {
	curPWLine->clear();
	newPWLine->clear();
	confirmPWLine->clear();
	errMsg->clear();
}

void ChangePWGUI::setErrMsg(const QString &msg) {
	errMsg->setText(msg);
}

void ChangePWGUI::setVerifyCb(VerifyCallback vcb) {
	this->vcb = vcb;
}

void ChangePWGUI::onOKClicked() {
	errMsg->clear();


	/* Extract passwords for validation */

	Password curPW, newPW, confirmPW;

	curPWLine->extract(curPW);

	if (newPWLine->extract(newPW)) {
		errMsg->setText("Password exceeds maximum length (256 characters)");
		return;
	}

	if (confirmPWLine->extract(confirmPW)) {
		errMsg->setText("Password exceeds maximum length (256 characters)");
		return;
	}


	/* Validate all fields are filled */

	if (curPW.isEmpty()) {
		errMsg->setText("Current password is not input");
		return;
	}

	if (newPW.isEmpty()) {
		errMsg->setText("New password is not input");
		return;
	}

	if (confirmPW.isEmpty()) {
		errMsg->setText("Confirm password is not input");
		return;
	}


	/* Validate new password matches confirmation */

	if (newPW.getSize() != confirmPW.getSize() || !newPW.equal(confirmPW)) {
		errMsg->setText("New and confirm password do not match");
		return;
	}


	/* Validate new password differs from current */

	if (newPW.getSize() == curPW.getSize() && newPW.equal(curPW)) {
		errMsg->setText("Old and new password are the same");
		return;
	}


	/* Verify current password via callback */

	if (vcb && !vcb(curPW)) {
		errMsg->setText("Current password is incorrect");
		curPWLine->clear();
		newPWLine->clear();
		confirmPWLine->clear();
		return;
	}


	/* Restore passwords for getInput() */

	curPWLine->setPassword(curPW);
	newPWLine->setPassword(newPW);

	accept();
}