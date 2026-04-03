/**
 * @file	MainGUI.cpp
 * @brief	Implementation of MainGUI class
 * @author	Astatine387
 */

#include "GUI/MainGUI.h"
#include <QClipboard>
#include <QGuiApplication>

MainGUI::MainGUI(QWidget *parent) : QWidget(parent) {
	/* Create layouts and components */

	changePWGUI = new ChangePWGUI(this);
	entryGUI = new EntryGUI(this);
	listGUI = new ListGUI(this);
	loginGUI = new LoginGUI(this);
	pwGUI = new PasswordGUI(this);
	stack = new QStackedWidget(this);
	vBox = new QVBoxLayout(this);


	/* Add GUIs to stacked widget for switching */

	stack->addWidget(loginGUI);
	stack->addWidget(pwGUI);
	stack->addWidget(listGUI);


	/* Configure layout */

	vBox->addWidget(stack);
	vBox->setContentsMargins(0, 0, 0, 0);

	setLayout(vBox);
	setWindowTitle("PasswordManager");


	/* Connect login signals */

	connect(loginGUI, &LoginGUI::vaultSelected, this, &MainGUI::onVaultSelected);
	connect(pwGUI, &PasswordGUI::loginRequested, this, &MainGUI::onLoginRequested);
	connect(pwGUI, &PasswordGUI::backRequested, this, &MainGUI::onBackToLogin);


	/* Connect list signals */

	connect(listGUI, &ListGUI::addRequested, this, &MainGUI::onAddRequested);
	connect(listGUI, &ListGUI::editRequested, this, &MainGUI::onEditRequested);
	connect(listGUI, &ListGUI::deleteRequested, this, &MainGUI::onDeleteRequested);
	connect(listGUI, &ListGUI::copyPWRequested, this, &MainGUI::onCopyPWRequested);
	connect(listGUI, &ListGUI::saveRequested, this, &MainGUI::onSaveRequested);
	connect(listGUI, &ListGUI::closeRequested, this, &MainGUI::onCloseRequested);
	connect(listGUI, &ListGUI::changePWRequested, this, &MainGUI::onChangePWRequested);


	/* Set error callback */

	vault.setErrorCb([this](const char *msg) {
		lastError = msg;
	});


	/* Set verify callback for password change */

	changePWGUI->setVerifyCb([this](const Password &curPW) -> bool {
		return vault.verifyPW(curPW);
	});
}

MainGUI::~MainGUI() {
	;
}

void MainGUI::onVaultSelected(int mode, const QString &path) {
	pwGUI->setVaultInfo(mode, path);

	stack->setCurrentWidget(pwGUI);
}

void MainGUI::onLoginRequested(const LoginInput &input) {
	int res;


	/* Set master password */

	Password pw;
	pw.setData(input.pw);
	vault.setPW(pw);


	/* Create or open vault */

	if (input.mode == 0) res = vault.newVault(input.path);
	else				 res = vault.openVault(input.path);

	if (res) {
		pwGUI->setErrMsg(QString::fromStdString(lastError));
		return;
	}


	/* Switch to list screen */

	vaultPath = input.path;

	refreshList();

	stack->setCurrentWidget(listGUI);
	resize(300, 300);
}

void MainGUI::onBackToLogin() {
	stack->setCurrentWidget(loginGUI);
}

void MainGUI::onAddRequested() {
	isEditMode = false;

	entryGUI->setAddMode();

	if (entryGUI->exec() == QDialog::Accepted) {
		Entry entry = entryGUI->getInput();

		if (vault.createEntry(entry.site, entry.acc, entry.pw)) {
			listGUI->setErrMsg("Entry already exists");
			return;
		}

		refreshList();
	}
}

void MainGUI::onEditRequested(const std::string &site, const std::string &acc) {
	isEditMode = true;
	origSite = site;
	origAcc = acc;


	/* Find the entry to get its password */

	
	Entry target = { site, acc };
	const auto &entries = vault.getEntries();
	auto it = entries.find(target);

	if (it == entries.end()) {
		listGUI->setErrMsg("Entry not found");
		return;
	}

	entryGUI->setEditMode(site, acc, it->pw);

	if (entryGUI->exec() == QDialog::Accepted) {
		Entry entry = entryGUI->getInput();
		int res = vault.updateEntry(origSite, origAcc, entry.site, entry.acc, entry.pw);

		if (res == 1) {
			listGUI->setErrMsg("Original entry not found");
			return;
		}

		if (res == 2) {
			listGUI->setErrMsg("Entry already exists");
			return;
		}

		refreshList();
	}
}

void MainGUI::onDeleteRequested(const std::string &site, const std::string &acc) {
	if (vault.deleteEntry(site, acc)) {
		listGUI->setErrMsg("Failed to delete entry");
		return;
	}

	refreshList();
}

void MainGUI::onCopyPWRequested(const std::string &site, const std::string &acc) {
	Entry target = { site, acc };
	const auto &entries = vault.getEntries();
	auto it = entries.find(target);

	if (it == entries.end()) {
		listGUI->setErrMsg("Entry not found");
		return;
	}


	/* Copy password to clipboard */

	QClipboard *board = QGuiApplication::clipboard();
	
	board->setText(QString::fromUtf8(it->pw.getData(), static_cast<int>(it->pw.getSize())));


	/* Auto-clear clipboard after 30 seconds */

	countdown = 30;

	listGUI->setErrMsg("Password copied (clears after 30s)");

	if (timer) {
		timer->stop();
		timer->disconnect();
	}
	else {
		timer = new QTimer(this);
	}

	connect(timer, &QTimer::timeout, this, [this, board]() {
		countdown--;

		if (countdown > 0) {
			listGUI->setErrMsg(QString("Password copied (clears after %1s)").arg(countdown));
		}
		else {
			timer->stop();
			board->clear();
			listGUI->setErrMsg("Clipboard cleared");
			timer->deleteLater();
			timer = nullptr;
		}
		});

	timer->setSingleShot(false);
	timer->start(1000);
}

void MainGUI::onSaveRequested() {
	if (vault.saveVault(vaultPath)) {
		pwGUI->setErrMsg(QString::fromStdString(lastError));
		return;
	}

	listGUI->setErrMsg("Saved");
}

void MainGUI::onCloseRequested() {
	vault.closeVault();
	vaultPath.clear();

	stack->setCurrentWidget(loginGUI);
	resize(300, 150);
}

void MainGUI::onChangePWRequested() {
	changePWGUI->reset();

	if (changePWGUI->exec() == QDialog::Accepted) {
		Password curPW, newPW;

		changePWGUI->getInput(curPW, newPW);

		if (vault.changePW(newPW, vaultPath)) {
			listGUI->setErrMsg("Failed to save vault");
			return;
		}

		listGUI->setErrMsg("Password changed");
	}
}

void MainGUI::closeEvent(QCloseEvent *event) {
	if (timer) {
		timer->stop();
		timer->disconnect();
		timer->deleteLater();
		timer = nullptr;

		QClipboard *board = QGuiApplication::clipboard();
		board->clear();
	}

	QWidget::closeEvent(event);
}

void MainGUI::refreshList() {
	std::vector<std::pair<std::string, std::string>> entryVec;
	const auto &entrySet = vault.getEntries();

	for (auto it = entrySet.begin(); it != entrySet.end(); it++) entryVec.emplace_back(it->site, it->acc);

	listGUI->loadEntries(entryVec);
}