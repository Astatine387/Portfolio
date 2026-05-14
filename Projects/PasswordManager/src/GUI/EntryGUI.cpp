/**
 * @file	EntryGUI.cpp
 * @brief	Implementation of EntryGUI class
 * @author	Astatine387
 */

#include "GUI/EntryGUI.h"

#include "Utils/library.h"

#include "Common/constants.h"

EntryGUI::EntryGUI(QWidget* parent) : QDialog(parent) {
  /* Create layouts and components */

  pwline_ = new PWLineEdit;
  spc_grid_ = new QGridLayout;
  err_msg_ = new QLabel;
  len_label_ = new QLabel("Length: 16");
  site_line_ = new QLineEdit;
  acc_line_ = new QLineEdit;
  check_all_btn_ = new QPushButton("Check All");
  uncheck_all_btn_ = new QPushButton("Uncheck All");
  reset_btn_ = new QPushButton("Reset to Default");
  gen_btn_ = new QPushButton("Generate");
  ok_btn_ = new QPushButton("Ok");
  len_slider_ = new QSlider(Qt::Horizontal);
  cancel_btn_ = new QPushButton("Cancel");
  btn_box_ = new QHBoxLayout;
  len_box_ = new QHBoxLayout;
  spc_btn_box_ = new QHBoxLayout;
  vbox_ = new QVBoxLayout;

  /* Configure input lines */

  site_line_->setPlaceholderText("Site");
  site_line_->setMaxLength(kMaxSiteLen);
  acc_line_->setPlaceholderText("Account");
  acc_line_->setMaxLength(kMaxAccLen);

  /* Configure password length slider */

  len_slider_->setRange(8, 32);
  len_slider_->setValue(16);

  len_box_->addWidget(len_label_);
  len_box_->addWidget(len_slider_);
  len_box_->setSpacing(10);
  len_box_->setContentsMargins(0, 0, 0, 0);

  /* Configure special character checkboxes */

  for (int i = 0; i < 32; i++) {
    QString label = QString(kSpcs[i]);

    spc_checks_[i] = new QCheckBox(label);
    spc_checks_[i]->setChecked(kDefaultSpcs[i]);

    spc_grid_->addWidget(spc_checks_[i], i / 8, i % 8);
  }

  spc_grid_->setSpacing(5);
  spc_grid_->setContentsMargins(0, 0, 0, 0);

  /* Configure special character control buttons */

  spc_btn_box_->addWidget(check_all_btn_);
  spc_btn_box_->addWidget(uncheck_all_btn_);
  spc_btn_box_->addWidget(reset_btn_);
  spc_btn_box_->addStretch();

  spc_btn_box_->setSpacing(10);
  spc_btn_box_->setContentsMargins(0, 0, 0, 0);

  /* Put OK, Cancel, and error message in the same line */

  btn_box_->addWidget(gen_btn_);
  btn_box_->addWidget(ok_btn_);
  btn_box_->addWidget(cancel_btn_);
  btn_box_->addStretch();

  btn_box_->setSpacing(10);
  btn_box_->setContentsMargins(0, 0, 0, 0);

  /* Configure main layout */

  vbox_->addWidget(site_line_);
  vbox_->addWidget(acc_line_);
  vbox_->addWidget(pwline_);
  vbox_->addLayout(len_box_);
  vbox_->addLayout(spc_grid_);
  vbox_->addLayout(spc_btn_box_);
  vbox_->addWidget(err_msg_);
  vbox_->addLayout(btn_box_);

  vbox_->setSpacing(10);
  vbox_->setContentsMargins(10, 10, 10, 10);

  setLayout(vbox_);

  /* Connect functions to buttons */

  connect(check_all_btn_, &QPushButton::clicked, this, &EntryGUI::OnCheckAllClicked);
  connect(uncheck_all_btn_, &QPushButton::clicked, this, &EntryGUI::OnUncheckAllClicked);
  connect(reset_btn_, &QPushButton::clicked, this, &EntryGUI::OnResetClicked);
  connect(ok_btn_, &QPushButton::clicked, this, &EntryGUI::OnOKClicked);
  connect(cancel_btn_, &QPushButton::clicked, this, &QDialog::reject);
  connect(gen_btn_, &QPushButton::clicked, this, &EntryGUI::OnGenerateClicked);

  connect(len_slider_, &QSlider::valueChanged, this,
          [this](int val) { len_label_->setText(QString("Length: %1").arg(val)); });
}

void EntryGUI::SetAddMode() {
  setWindowTitle("Add Entry");

  site_line_->clear();
  acc_line_->clear();
  pwline_->Clear();
  err_msg_->clear();
}

void EntryGUI::SetEditMode(const std::string& site, const std::string& acc, const Password& pw) {
  setWindowTitle("Edit Entry");

  site_line_->setText(QString::fromStdString(site));
  acc_line_->setText(QString::fromStdString(acc));
  pwline_->SetPassword(pw);
  err_msg_->clear();
}

Entry EntryGUI::GetInput() {
  Entry entry;

  entry.site = site_line_->text().toStdString();
  entry.acc = acc_line_->text().toStdString();
  pwline_->Extract(entry.pw);

  return entry;
}

void EntryGUI::OnOKClicked() {
  err_msg_->clear();

  if (site_line_->text().isEmpty()) {
    err_msg_->setText("Site is not input");
    return;
  }

  if (acc_line_->text().isEmpty()) {
    err_msg_->setText("Account is not input");
    return;
  }

  Password tmp;

  if (pwline_->Extract(tmp)) {
    err_msg_->setText("Password exceeds maximum length (256 characters)");
    return;
  }

  if (tmp.IsEmpty()) {
    err_msg_->setText("Password is not input");
    return;
  }

  if (!HasSpecial(tmp)) {
    err_msg_->setText("Password must contain at least one special character");
    return;
  }

  pwline_->SetPassword(tmp);

  accept();
}

void EntryGUI::OnGenerateClicked() {
  if (!HasSpecialSelected()) {
    err_msg_->setText("No special characters selected");
    return;
  }

  err_msg_->clear();

  std::vector<bool> spc_list = GetSpecialsList();
  int size = len_slider_->value();
  Password generated;

  if (GenPW(generated, spc_list, size)) {
    err_msg_->setText("Failed to generate password");
    return;
  }

  pwline_->SetPassword(generated);
}

void EntryGUI::OnCheckAllClicked() {
  for (int i = 0; i < 32; i++) {
    spc_checks_[i]->setChecked(true);
  }
}

void EntryGUI::OnUncheckAllClicked() {
  for (int i = 0; i < 32; i++) {
    spc_checks_[i]->setChecked(false);
  }
}

void EntryGUI::OnResetClicked() {
  for (int i = 0; i < 32; i++) {
    spc_checks_[i]->setChecked(kDefaultSpcs[i]);
  }
}

std::vector<bool> EntryGUI::GetSpecialsList() {
  std::vector<bool> list(32);

  for (int i = 0; i < 32; i++) {
    list[i] = spc_checks_[i]->isChecked();
  }

  return list;
}

bool EntryGUI::HasSpecial(const Password& pw) const {
  const char* data = pw.GetData();
  size_t size = pw.GetSize();

  if (!data || size == 0) {
    return false;
  }

  for (size_t i = 0; i < size; i++) {
    for (int j = 0; j < 32; j++)
      if (data[i] == kSpcs[j]) {
        return true;
      }
  }

  return false;
}

bool EntryGUI::HasSpecialSelected() const {
  for (int i = 0; i < 32; i++) {
    if (spc_checks_[i]->isChecked()) {
      return true;
    }
  }

  return false;
}

int EntryGUI::GenPW(Password& dst, const std::vector<bool>& spc_list, int pw_size) {
  std::string pool;
  size_t pool_size = 62;
  const char lower[] = "abcdefghijklmnopqrstuvwxyz";
  const char upper[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const char num[] = "0123456789";
  char* pw;
  int crs = 0, res = 0;

  /* Check the special character list size is valid */

  if (spc_list.size() != 32) {
    return 1;
  }

  /* Check the password size is valid */

  if (pw_size < 8) {
    return 1;
  }

  /* Add characters to pool */

  for (int i = 0; i < 32; i++) {
    if (spc_list[i]) {
      pool_size++;
    }
  }

  pool.resize(pool_size);

  for (int i = 0; i < 26; i++) {
    pool[crs++] = lower[i];
  }

  for (int i = 0; i < 26; i++) {
    pool[crs++] = upper[i];
  }

  for (int i = 0; i < 10; i++) {
    pool[crs++] = num[i];
  }

  for (int i = 0; i < 32; i++) {
    if (spc_list[i]) {
      pool[crs++] = kSpcs[i];
    }
  }

  /* Check at least one special character is selected */

  if (pool_size <= 62) {
    return 1;
  }

  /* Generate password */

  pw = new char[pw_size]{};

  pw[0] = lower[RandomRange(0, 25)];
  pw[1] = upper[RandomRange(0, 25)];
  pw[2] = num[RandomRange(0, 9)];
  pw[3] = pool[RandomRange(62, static_cast<uint32_t>(pool_size) - 1)];

  for (int i = 4; i < pw_size; i++) {
    pw[i] = pool[RandomRange(0, static_cast<uint32_t>(pool_size) - 1)];
  }

  Shuffle(reinterpret_cast<uint8_t*>(pw), pw_size);

  res = dst.SetData(pw, pw_size);

  /* Cleanup */

  Wipe(pool.data(), pool.size());
  Wipe(pw, pw_size);

  delete[] pw;

  return res;
}