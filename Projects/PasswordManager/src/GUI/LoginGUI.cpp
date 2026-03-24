/**
 * @file	LoginGUI.cpp
 * @brief	Implementation of LoginGUI class
 * @author	Astatine387
 */

#include "GUI/LoginGUI.h"
#include <QFileDialog>

LoginGUI::LoginGUI(QWidget *parent) : QWidget(parent) {
	/* Create layout and components */

	newBtn = new QPushButton("New");
	openBtn = new QPushButton("Open");
	hBox = new QHBoxLayout;


	/* Configure layout */

	hBox->addStretch();
	hBox->addWidget(newBtn);
	hBox->addStretch();
	hBox->addWidget(openBtn);
	hBox->addStretch();

	setLayout(hBox);


	/* Connect functions to buttons */

	connect(newBtn, &QPushButton::clicked, this, &LoginGUI::onNewClicked);
	connect(openBtn, &QPushButton::clicked, this, &LoginGUI::onOpenClicked);
}

void LoginGUI::onNewClicked() {
	QString path = QFileDialog::getSaveFileName(this, "Create New Vault", "", "Vault Files (*.vault)");

	if (!path.isEmpty()) emit vaultSelected(0, path);
}

void LoginGUI::onOpenClicked() {
	QString path = QFileDialog::getOpenFileName(this, "Open Vault", "", "Vault Files (*.vault)");

	if (!path.isEmpty()) emit vaultSelected(1, path);
}