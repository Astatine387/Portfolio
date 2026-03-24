/**
 * @file	EntryGUI.cpp
 * @brief	Implementation of EntryGUI class
 * @author	Astatine387
 */

#include "Common/constants.h"
#include "GUI/EntryGUI.h"
#include "Utils/library.h"

EntryGUI::EntryGUI(QWidget *parent) : QDialog(parent) {
	/* Create layouts and components */

	pwLine = new PWLineEdit;
	spcGrid = new QGridLayout;
	errMsg = new QLabel;
	lenLabel = new QLabel("Length: 16");
	siteLine = new QLineEdit;
	accLine = new QLineEdit;
	checkAllBtn = new QPushButton("Check All");
	uncheckAllBtn = new QPushButton("Uncheck All");
	resetBtn = new QPushButton("Reset to Default");
	genBtn = new QPushButton("Generate");
	okBtn = new QPushButton("Ok");
	lenSlider = new QSlider(Qt::Horizontal);
	cancelBtn = new QPushButton("Cancel");
	btnBox = new QHBoxLayout;
	lenBox = new QHBoxLayout;
	spcBtnBox = new QHBoxLayout;
	vBox = new QVBoxLayout;


	/* Configure input lines */

	siteLine->setPlaceholderText("Site");
	siteLine->setMaxLength(kMaxSiteLen);
	accLine->setPlaceholderText("Account");
	accLine->setMaxLength(kMaxAccLen);


	/* Configure password length slider */

	lenSlider->setRange(8, 32);
	lenSlider->setValue(16);

	lenBox->addWidget(lenLabel);
	lenBox->addWidget(lenSlider);
	lenBox->setSpacing(10);
	lenBox->setContentsMargins(0, 0, 0, 0);


	/* Configure special character checkboxes */

	for (int i = 0; i < 32; i++) {
		QString label = QString(spcs[i]);

		spcChecks[i] = new QCheckBox(label);
		spcChecks[i]->setChecked(defaultSpc[i]);

		spcGrid->addWidget(spcChecks[i], i / 8, i % 8);
	}

	spcGrid->setSpacing(5);
	spcGrid->setContentsMargins(0, 0, 0, 0);


	/* Configure special character control buttons */

	spcBtnBox->addWidget(checkAllBtn);
	spcBtnBox->addWidget(uncheckAllBtn);
	spcBtnBox->addWidget(resetBtn);
	spcBtnBox->addStretch();

	spcBtnBox->setSpacing(10);
	spcBtnBox->setContentsMargins(0, 0, 0, 0);


	/* Put OK, Cancel, and error message in the same line */

	btnBox->addWidget(genBtn);
	btnBox->addWidget(okBtn);
	btnBox->addWidget(cancelBtn);
	btnBox->addStretch();

	btnBox->setSpacing(10);
	btnBox->setContentsMargins(0, 0, 0, 0);


	/* Configure main layout */

	vBox->addWidget(siteLine);
	vBox->addWidget(accLine);
	vBox->addWidget(pwLine);
	vBox->addLayout(lenBox);
	vBox->addLayout(spcGrid);
	vBox->addLayout(spcBtnBox);
	vBox->addWidget(errMsg);
	vBox->addLayout(btnBox);

	vBox->setSpacing(10);
	vBox->setContentsMargins(10, 10, 10, 10);

	setLayout(vBox);


	/* Connect functions to buttons */

	connect(checkAllBtn, &QPushButton::clicked, this, &EntryGUI::onCheckAllClicked);
	connect(uncheckAllBtn, &QPushButton::clicked, this, &EntryGUI::onUncheckAllClicked);
	connect(resetBtn, &QPushButton::clicked, this, &EntryGUI::onResetClicked);
	connect(okBtn, &QPushButton::clicked, this, &EntryGUI::onOKClicked);
	connect(cancelBtn, &QPushButton::clicked, this, &QDialog::reject);
	connect(genBtn, &QPushButton::clicked, this, &EntryGUI::onGenerateClicked);

	connect(lenSlider, &QSlider::valueChanged, this, [this](int val) {
		lenLabel->setText(QString("Length: %1").arg(val));
	});
}

void EntryGUI::setAddMode() {
	setWindowTitle("Add Entry");

	siteLine->clear();
	accLine->clear();
	pwLine->clear();
	errMsg->clear();
}

void EntryGUI::setEditMode(const std::string &site, const std::string &acc, const Password &pw) {
	setWindowTitle("Edit Entry");

	siteLine->setText(QString::fromStdString(site));
	accLine->setText(QString::fromStdString(acc));
	pwLine->setPassword(pw);
	errMsg->clear();
}

Entry EntryGUI::getInput() {
	Entry entry;

	entry.site = siteLine->text().toStdString();
	entry.acc = accLine->text().toStdString();
	pwLine->extract(entry.pw);

	return entry;
}

void EntryGUI::onOKClicked() {
	errMsg->clear();

	if (siteLine->text().isEmpty()) {
		errMsg->setText("Site is not input");
		return;
	}

	if (accLine->text().isEmpty()) {
		errMsg->setText("Account is not input");
		return;
	}

	Password tmp;

	if (pwLine->extract(tmp)) {
		errMsg->setText("Password exceeds maximum length (256 characters)");
		return;
	}

	if (tmp.isEmpty()) {
		errMsg->setText("Password is not input");
		return;
	}

	if (!hasSpecial(tmp)) {
		errMsg->setText("Password must contain at least one special character");
		return;
	}

	pwLine->setPassword(tmp);

	accept();
}

void EntryGUI::onGenerateClicked() {
	if (!hasSpecialSelected()) {
		errMsg->setText("No special characters selected");
		return;
	}

	errMsg->clear();

	std::vector<bool> spcList = getSpecialsList();
	int size = lenSlider->value();
	Password generated;

	if (genPW(generated, spcList, size)) {
		errMsg->setText("Failed to generate password");
		return;
	}

	pwLine->setPassword(generated);
}

void EntryGUI::onCheckAllClicked() {
	for (int i = 0; i < 32; i++) spcChecks[i]->setChecked(true);
}

void EntryGUI::onUncheckAllClicked() {
	for (int i = 0; i < 32; i++) spcChecks[i]->setChecked(false);
}

void EntryGUI::onResetClicked() {
	for (int i = 0; i < 32; i++) spcChecks[i]->setChecked(defaultSpc[i]);
}

std::vector<bool> EntryGUI::getSpecialsList() {
	std::vector<bool> list(32);

	for (int i = 0; i < 32; i++) list[i] = spcChecks[i]->isChecked();

	return list;
}

bool EntryGUI::hasSpecial(const Password &pw) const {
	const char *data = pw.getData();
	size_t size = pw.getSize();

	if (!data || size == 0) return false;

	for (size_t i = 0; i < size; i++) {
		for (int j = 0; j < 32; j++) if (data[i] == spcs[j]) return true;
	}

	return false;
}

bool EntryGUI::hasSpecialSelected() const {
	for (int i = 0; i < 32; i++) {
		if (spcChecks[i]->isChecked()) return true;
	}

	return false;
}

int EntryGUI::genPW(Password &dst, const std::vector<bool> &spcList, int pwSize) {
	std::string pool;
	size_t poolSize = 62;
	const char lower[] = "abcdefghijklmnopqrstuvwxyz";
	const char upper[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	const char num[] = "0123456789";
	char *pw;
	int crs = 0, res = 0;


	/* Check the special character list size is valid */

	if (spcList.size() != 32) return 1;


	/* Check the password size is valid */

	if (pwSize < 8) return 1;


	/* Add characters to pool */

	for (int i = 0; i < 32; i++) if (spcList[i]) poolSize++;

	pool.resize(poolSize);

	for (int i = 0; i < 26; i++) pool[crs++] = lower[i];
	for (int i = 0; i < 26; i++) pool[crs++] = upper[i];
	for (int i = 0; i < 10; i++) pool[crs++] = num[i];
	for (int i = 0; i < 32; i++) if (spcList[i]) pool[crs++] = spcs[i];


	/* Check at least one special character is selected */

	if (poolSize <= 62) return 1;


	/* Generate password */

	pw = new char[pwSize] {};

	pw[0] = lower[RandomRange(0, 25)];
	pw[1] = upper[RandomRange(0, 25)];
	pw[2] = num[RandomRange(0, 9)];
	pw[3] = pool[RandomRange(62, static_cast<uint32_t>(poolSize) - 1)];

	for (int i = 4; i < pwSize; i++) pw[i] = pool[RandomRange(0, static_cast<uint32_t>(poolSize) - 1)];

	Shuffle(reinterpret_cast<uint8_t *>(pw), pwSize);

	res = dst.setData(pw, pwSize);


	/* Cleanup */

	Wipe(pool.data(), pool.size());
	Wipe(pw, pwSize);

	delete[] pw;


	return res;
}