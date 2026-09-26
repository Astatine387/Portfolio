/**
 * @file    gui_input_test.cpp
 * @brief   Unit tests for the length limits on the GUI input fields
 * @author  Astatine387
 */

#include <gtest/gtest.h>

#include <QApplication>
#include <QChar>
#include <QDialog>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QString>
#include <QWidget>
#include <QtGlobal>
#include <cstddef>

#include "common/constants.h"
#include "gui/entry_gui.h"
#include "gui/pw_line_edit.h"
#include "utils/password.h"

namespace {
constexpr qsizetype kOversizedLen = 300;  // Characters past every field limit, but only once counted in bytes

constexpr char16_t kHangul = 0xD55C;  // U+D55C, three bytes of UTF-8 against one UTF-16 character

/**
 * @brief   Find an input line under a widget by its placeholder text
 * @param   parent          Widget to search
 * @param   placeholder     Placeholder text the line was configured with
 * @return  The matching line, or nullptr when there is none
 */
QLineEdit* FindLine(const QWidget& parent, const QString& placeholder) {
  for (QLineEdit* line : parent.findChildren<QLineEdit*>()) {
    if (line->placeholderText() == placeholder) {
      return line;
    }
  }

  return nullptr;
}

/**
 * @brief   Find a button under a widget by its label
 * @param   parent  Widget to search
 * @param   text    Text the button carries
 * @return  The matching button, or nullptr when there is none
 */
QPushButton* FindButton(const QWidget& parent, const QString& text) {
  for (QPushButton* btn : parent.findChildren<QPushButton*>()) {
    if (btn->text() == text) {
      return btn;
    }
  }

  return nullptr;
}

/**
 * @brief   Check whether any label under a widget reports the given message
 * @param   parent  Widget to search
 * @param   text    Message to look for
 * @return  true when a label carries it
 */
bool HasMessage(const QWidget& parent, const QString& text) {
  for (const QLabel* label : parent.findChildren<QLabel*>()) {
    if (label->text().contains(text)) {
      return true;
    }
  }

  return false;
}
}  // namespace

/* ==================================================
 * PWLineEdit Test
 * ================================================== */

/* A paste goes through QLineEdit::insert, and insert is where a maximum length would cut one short, so the tests
 * below paste by calling it rather than by going through a clipboard the CI machine does not have. */

/**
 * @brief   Verify a paste past the limit is refused rather than cut down to it
 */
TEST(PWLineEditTest, OversizedPasteIsRefused) {
  PWLineEdit widget;
  QLineEdit* line = FindLine(widget, "Password");

  ASSERT_NE(line, nullptr);

  line->insert(QString(kOversizedLen, QChar(u'a')));

  ASSERT_EQ(line->text().size(), kOversizedLen);

  Password pw;

  EXPECT_EQ(widget.Extract(pw), Result::kFailure);
  EXPECT_TRUE(pw.IsEmpty());
}

/**
 * @brief   Verify a paste of exactly the limit is kept whole
 */
TEST(PWLineEditTest, PasteAtLimitIsKept) {
  PWLineEdit widget;
  QLineEdit* line = FindLine(widget, "Password");

  ASSERT_NE(line, nullptr);

  line->insert(QString(kMaxMasterPwLen, QChar(u'a')));

  Password pw;

  ASSERT_EQ(widget.Extract(pw), Result::kSuccess);
  EXPECT_EQ(pw.GetSize(), static_cast<size_t>(kMaxMasterPwLen));
}

/**
 * @brief   Verify the limit is counted in UTF-8 bytes rather than in characters
 */
TEST(PWLineEditTest, LimitIsCountedInBytes) {
  constexpr qsizetype kUtf8Len = 3;                           // Bytes U+D55C takes in UTF-8
  constexpr qsizetype kFitting = kMaxMasterPwLen / kUtf8Len;  // 255 bytes, the most whole characters that fit

  PWLineEdit widget;
  QLineEdit* line = FindLine(widget, "Password");

  ASSERT_NE(line, nullptr);

  line->insert(QString(kFitting, QChar(kHangul)));

  Password fits;

  ASSERT_EQ(widget.Extract(fits), Result::kSuccess);
  EXPECT_EQ(fits.GetSize(), static_cast<size_t>(kFitting * kUtf8Len));

  /* Extract clears the field whatever it returned, so the next paste starts from an empty line */

  line->insert(QString(kFitting + 1, QChar(kHangul)));

  Password overflows;

  EXPECT_EQ(widget.Extract(overflows), Result::kFailure);
  EXPECT_TRUE(overflows.IsEmpty());
}

/* ==================================================
 * EntryGUI Test
 * ================================================== */

/**
 * @brief   Verify a site past the limit is refused rather than stored cut down to it
 */
TEST(EntryGUITest, OversizedSiteIsRefused) {
  EntryGUI dialog;
  QLineEdit* site = FindLine(dialog, "Site");
  QLineEdit* acc = FindLine(dialog, "Account");
  QLineEdit* pw = FindLine(dialog, "Password");
  QPushButton* ok = FindButton(dialog, "Ok");

  ASSERT_NE(site, nullptr);
  ASSERT_NE(acc, nullptr);
  ASSERT_NE(pw, nullptr);
  ASSERT_NE(ok, nullptr);

  site->insert(QString(kOversizedLen, QChar(u'a')));
  acc->insert("account");
  pw->insert("password");

  ok->click();

  EXPECT_NE(dialog.result(), QDialog::Accepted);
  EXPECT_EQ(site->text().size(), kOversizedLen);
  EXPECT_TRUE(HasMessage(dialog, "Site exceeds maximum size"));
}

/**
 * @brief   Verify an account past the limit is refused rather than stored cut down to it
 */
TEST(EntryGUITest, OversizedAccountIsRefused) {
  EntryGUI dialog;
  QLineEdit* site = FindLine(dialog, "Site");
  QLineEdit* acc = FindLine(dialog, "Account");
  QLineEdit* pw = FindLine(dialog, "Password");
  QPushButton* ok = FindButton(dialog, "Ok");

  ASSERT_NE(site, nullptr);
  ASSERT_NE(acc, nullptr);
  ASSERT_NE(pw, nullptr);
  ASSERT_NE(ok, nullptr);

  site->insert("site");
  acc->insert(QString(kOversizedLen, QChar(u'a')));
  pw->insert("password");

  ok->click();

  EXPECT_NE(dialog.result(), QDialog::Accepted);
  EXPECT_EQ(acc->text().size(), kOversizedLen);
  EXPECT_TRUE(HasMessage(dialog, "Account exceeds maximum size"));
}

/**
 * @brief   Verify a password past the limit is refused rather than stored cut down to it
 */
TEST(EntryGUITest, OversizedPasswordIsRefused) {
  EntryGUI dialog;
  QLineEdit* site = FindLine(dialog, "Site");
  QLineEdit* acc = FindLine(dialog, "Account");
  QLineEdit* pw = FindLine(dialog, "Password");
  QPushButton* ok = FindButton(dialog, "Ok");

  ASSERT_NE(site, nullptr);
  ASSERT_NE(acc, nullptr);
  ASSERT_NE(pw, nullptr);
  ASSERT_NE(ok, nullptr);

  site->insert("site");
  acc->insert("account");
  pw->insert(QString(kOversizedLen, QChar(u'a')));

  ok->click();

  EXPECT_NE(dialog.result(), QDialog::Accepted);
  EXPECT_TRUE(HasMessage(dialog, "Password exceeds maximum length"));
}

/**
 * @brief   Run the suite against the offscreen platform, since neither CI nor test discovery has a display
 * @param   argc    Argument count
 * @param   argv    Argument values
 * @return  0 when every test passed
 */
int main(int argc, char** argv) {
  /* gtest_discover_tests runs this binary at build time, where a display is even less likely than it is under CI */

  if (qEnvironmentVariableIsEmpty("QT_QPA_PLATFORM")) {
    qputenv("QT_QPA_PLATFORM", "offscreen");
  }

  QApplication app(argc, argv);

  ::testing::InitGoogleTest(&argc, argv);

  return RUN_ALL_TESTS();
}
