/**
 * @file	PasswordGUI.cpp
 * @brief	Implementation of PasswordGUI class
 * @author	Astatine387
 */

#include "GUI/PasswordGUI.h"

PasswordGUI::PasswordGUI(QWidget *parent) : QWidget(parent) {
	/* Create layouts and components */

	pwLine = new PWLineEdit;
	pathLabel = new QLabel;
	errMsg = new QLabel;
	backBtn = new QPushButton("Back");
	confirmBtn = new QPushButton("Confirm");
	btnBox = new QHBoxLayout;
	vBox = new QVBoxLayout;

	errMsg->setContentsMargins(5, 0, 0, 0);


	/* Put buttons and error message in the same line */

	btnBox->addWidget(confirmBtn);
	btnBox->addWidget(backBtn);
	btnBox->addStretch();

	btnBox->setSpacing(10);
	btnBox->setContentsMargins(0, 0, 0, 0);


	/* Configure main layout */

	vBox->addStretch();
	vBox->addWidget(pwLine);
	vBox->addLayout(btnBox);
	vBox->addWidget(errMsg);
	vBox->addStretch();

	vBox->setSpacing(15);
	vBox->setContentsMargins(10, 10, 10, 10);

	setLayout(vBox);


	/* Connect functions to buttons */

	connect(confirmBtn, &QPushButton::clicked, this, &PasswordGUI::onConfirmClicked);
	connect(backBtn, &QPushButton::clicked, this, &PasswordGUI::backRequested);
}

void PasswordGUI::setVaultInfo(int mode, const QString &path) {
	this->mode = mode;
	this->path = path;

	QString modeStr = (mode == 0) ? "New" : "Open";

	pathLabel->setText(modeStr + ": " + path);

	pwLine->clear();
	errMsg->clear();
}

void PasswordGUI::setErrMsg(const QString &msg) {
	errMsg->setText(msg);
}

void PasswordGUI::onConfirmClicked() {
	errMsg->clear();


	/* Check password is input */

	LoginInput input;

	if (pwLine->extract(input.pw)) {
		errMsg->setText("Password exceeds maximum length (256 characters)");
		return;
	}

	if (input.pw.isEmpty()) {
		errMsg->setText("Password is not input");
		return;
	}


	/* Emit login request */

	input.mode = mode;
	input.path = path;

	emit loginRequested(input);
}