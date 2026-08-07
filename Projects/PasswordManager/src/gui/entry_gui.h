/**
 * @file	entry_gui.h
 * @brief	Password entry add & edit window
 * @author	Astatine387
 */

#pragma once

#include <QCheckBox>
#include <QDialog>
#include <QGridLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QSlider>
#include <QString>
#include <QVBoxLayout>
#include <QVector>
#include <QWidget>
#include <array>
#include <string>

#include "gui/entry_interface.h"
#include "gui/pw_line_edit.h"
#include "utils/password.h"

/**
 * @class	EntryGUI
 * @brief	Dialog for adding and editing password entries
 */
class EntryGUI : public QDialog {
  Q_OBJECT

 public:
  /**
   * @brief	Constructor of EntryGUI class
   * @param	parent	Parent widget
   */
  explicit EntryGUI(QWidget* parent = nullptr);

  /**
   * @brief	Set dialog to add mode
   */
  void SetAddMode();

  /**
   * @brief	Set dialog to edit mode with existing data
   * @param	site	Current site name
   * @param	acc		Current account
   * @param	pw		Current password
   */
  void SetEditMode(const QString& site, const QString& acc, const Password& pw);

  /**
   * @brief	Get the entry input from the dialog
   * @return	Entry input parameters
   */
  EntryInput GetInput();

 private slots:
  /**
   * @brief	Validate input and accept dialog
   */
  void OnOKClicked();

  /**
   * @brief	Validate special character selection and emit generate request
   */
  void OnGenerateClicked();

  /**
   * @brief	Check all special character checkboxes
   */
  void OnCheckAllClicked();

  /**
   * @brief	Uncheck all special character checkboxes
   */
  void OnUncheckAllClicked();

  /**
   * @brief	Reset special character checkboxes to default
   */
  void OnResetClicked();

 private:
  std::array<QCheckBox*, 32> spc_checks_;
  PWLineEdit* pwline_;
  QGridLayout* spc_grid_;
  QLabel* err_msg_;
  QLabel* len_label_;
  QLineEdit* site_line_;
  QLineEdit* acc_line_;
  QPushButton* check_all_btn_;
  QPushButton* uncheck_all_btn_;
  QPushButton* reset_btn_;
  QPushButton* gen_btn_;
  QPushButton* ok_btn_;
  QPushButton* cancel_btn_;
  QSlider* len_slider_;
  QHBoxLayout* btn_box_;
  QHBoxLayout* len_box_;
  QHBoxLayout* spc_btn_box_;
  QVBoxLayout* vbox_;

  Password input_pw_;  // Validated password handed to GetInput

  /**
   * @brief     Get the special character selection list
   * @return	Special character selection list
   */
  QVector<bool> GetSpecialsList();

  /**
   * @brief	    Check if at least one special character is selected
   * @return	true if at least one is checked
   */
  [[nodiscard]] bool HasSpecialSelected() const;

  /**
   * @brief	    Generate a random password including at least one each of uppercase, lowercase, number, and special
   * character
   *
   * @param     dst		    Destination password
   * @param     spc_list    List of specials to be used
   * @param     pw_size	    Destination password size
   * @return	            kSuccess on success, kFailure on failure
   */
  Result GenPw(Password& dst, const QVector<bool>& spc_list, int pw_size);
};
