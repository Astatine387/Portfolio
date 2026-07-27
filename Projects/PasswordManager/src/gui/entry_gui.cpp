/**
 * @file	entry_gui.cpp
 * @brief	Implementation of EntryGUI class
 * @author	Astatine387
 */

#include "gui/entry_gui.h"

#include <sodium.h>

#include <string>
#include <string_view>
#include <utility>

#include "common/constants.h"
#include "core/secure_key.h"
#include "utils/platform.h"

namespace {
constexpr std::string_view kSpcs = R"(`~!@#$%^&*()-_=+[{]}\|;:'",<.>/?)";

const std::array<bool, 32> kDefaultSpcs = {
  false, true, true, true, false, false, true, true,
  //  `     ~     !     @      #      $     %     ^
  false, false, false, false, false, true, true, true,
  //  &      *      (       )     -     _     =     +
  true, true, true, true, false, false, false, true,
  // [     {     ]     }      \      |      ;     :
  false, false, true, false, false, false, false, true
  //  '      "     ,      <      .      >      /     ?
};
}  // namespace

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

  len_slider_->setRange(kMinPwLen, kMaxPwLen);
  len_slider_->setValue(kDefaultPwLen);

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
  input_pw_.Clean();
}

void EntryGUI::SetEditMode(const QString& site, const QString& acc, const Password& pw) {
  setWindowTitle("Edit Entry");

  site_line_->setText(site);
  acc_line_->setText(acc);
  pwline_->SetPassword(pw);
  err_msg_->clear();
  input_pw_.Clean();
}

EntryInput EntryGUI::GetInput() {
  EntryInput res;

  res.site = site_line_->text();
  res.acc = acc_line_->text();
  res.pw = std::move(input_pw_);

  return res;
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

  /* Limit by UTF-8 byte size, since the vault stores and validates bytes (not characters) */

  if (site_line_->text().toUtf8().size() > kMaxSiteLen) {
    err_msg_->setText("Site exceeds maximum size (256 bytes)");
    return;
  }

  if (acc_line_->text().toUtf8().size() > kMaxAccLen) {
    err_msg_->setText("Account exceeds maximum size (256 bytes)");
    return;
  }

  Password tmp;

  if (pwline_->Extract(tmp) == Result::kFailure) {
    err_msg_->setText("Password exceeds maximum length (256 characters)");
    return;
  }

  if (tmp.IsEmpty()) {
    err_msg_->setText("Password is not input");
    return;
  }

  input_pw_ = std::move(tmp);

  accept();
}

void EntryGUI::OnGenerateClicked() {
  if (!HasSpecialSelected()) {
    err_msg_->setText("No special characters selected");
    return;
  }

  err_msg_->clear();

  QVector<bool> spc_list = GetSpecialsList();
  Password res;
  int size = len_slider_->value();

  if (GenPw(res, spc_list, size) == Result::kFailure) {
    err_msg_->setText("Failed to generate password");
    return;
  }

  pwline_->SetPassword(res);
}

void EntryGUI::OnCheckAllClicked() {
  for (auto spc : spc_checks_) {
    spc->setChecked(true);
  }
}

void EntryGUI::OnUncheckAllClicked() {
  for (auto spc : spc_checks_) {
    spc->setChecked(false);
  }
}

void EntryGUI::OnResetClicked() {
  for (int i = 0; i < 32; i++) {
    spc_checks_[i]->setChecked(kDefaultSpcs[i]);
  }
}

QVector<bool> EntryGUI::GetSpecialsList() {
  QVector<bool> list(32);

  for (int i = 0; i < 32; i++) {
    list[i] = spc_checks_[i]->isChecked();
  }

  return list;
}

bool EntryGUI::HasSpecialSelected() const {
  for (auto spc : spc_checks_) {
    if (spc->isChecked()) {
      return true;
    }
  }

  return false;
}

Result EntryGUI::GenPw(Password& dst, const QVector<bool>& spc_list, int pw_size) {
  constexpr size_t kPoolMax = 94;  // 62 alphanumeric + up to 32 special characters

  std::string lower = "abcdefghijklmnopqrstuvwxyz";
  std::string upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  std::string num = "0123456789";
  std::array<char, kPoolMax> pool{};
  size_t pool_size = 62;
  char* pw;
  int crs = 0;

  /* Check the special character list size is valid */

  if (spc_list.size() != 32) {
    return Result::kFailure;
  }

  /* Check the password size is valid */

  if (pw_size < 8) {
    return Result::kFailure;
  }

  /* Add characters to pool */

  for (int i = 0; i < 32; i++) {
    if (spc_list[i]) {
      pool_size++;
    }
  }

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
    return Result::kFailure;
  }

  /* Generate the password in guarded, locked memory */

  InitCrypto();

  pw = static_cast<char*>(sodium_malloc(pw_size));

  if (pw == nullptr) {
    return Result::kFailure;
  }

  Result res = Result::kSuccess;

  /* Pick a random character from src into out */

  auto fill = [&res](char& out, const auto& src, uint32_t lo, uint32_t hi) {
    uint32_t idx;

    if (RandomRange(&idx, lo, hi) == Result::kFailure) {
      // LCOV_EXCL_START
      res = Result::kFailure;
      return;
      // LCOV_EXCL_STOP
    }

    out = src[idx];
  };

  /* Check whether the password has at least one each of four categories */

  auto has_all = [](const char* buf, int len) {
    bool has_lower = false;
    bool has_upper = false;
    bool has_num = false;
    bool has_spc = false;

    for (int i = 0; i < len; i++) {
      unsigned char c = static_cast<unsigned char>(buf[i]);

      if (c >= 'a' && c <= 'z') {
        has_lower = true;
      }
      else if (c >= 'A' && c <= 'Z') {
        has_upper = true;
      }
      else if (c >= '0' && c <= '9') {
        has_num = true;
      }
      else {
        has_spc = true;
      }
    }

    return has_lower && has_upper && has_num && has_spc;
  };

  /* Re-generate if the password doesn't have at least one each of four categories */

  do {
    for (int i = 0; i < pw_size; i++) {
      fill(pw[i], pool, 0, static_cast<uint32_t>(pool_size) - 1);
    }
  } while (res == Result::kSuccess && !has_all(pw, pw_size));

  /* Store only if every draw succeeded */

  if (res == Result::kSuccess) {
    res = dst.SetData(pw, pw_size);
  }

  /* Cleanup */

  sodium_memzero(pool.data(), pool.size());
  sodium_free(pw);

  return res;
}