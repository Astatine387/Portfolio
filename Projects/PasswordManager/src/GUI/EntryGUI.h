/**
 * @file	EntryGUI.h
 * @brief	Password entry add & edit window
 * @author	Astatine387
 */

#pragma once

#include "Core/Entry.h"
#include "GUI/PWLineEdit.h"
#include "Utils/Password.h"

#include <QCheckBox>
#include <QDialog>
#include <QGridLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QSlider>
#include <QVBoxLayout>
#include <QWidget>

#include <string>
#include <vector>

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
  void SetEditMode(const std::string& site, const std::string& acc, const Password& pw);

  /**
   * @brief	Get the entry input from the dialog
   * @return	Entry input parameters
   */
  Entry GetInput();

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
  PWLineEdit* pwline_;
  QCheckBox* spc_checks_[32];
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

  static constexpr char spcs_[] = "`~!@#$%^&*()-_=+[{]}\\|;:\'\",<.>/?";

  static constexpr bool default_spc_[32] = {
                                    //    `  ~  !  @  #  $  %  ^
                                          0, 1, 1, 1, 0, 0, 1, 1,
                                    //    &  *  (  )  -  _  =  +
                                          0, 0, 0, 0, 0, 1, 1, 1,
                                    //    [  {  ]  }  \  |  ;  :
                                          1, 1, 1, 1, 0, 0, 0, 1,
                                    //    '  "  ,  <  .  >  /  ?
                                          0, 0, 1, 0, 0, 0, 0, 1};

  /**
   * @brief     Get the special character selection list
   * @return	Special character selection list
   */
  std::vector<bool> GetSpecialsList();

  /**
   * @brief	    Check whether the password has at least one special character
   * @return	true if the password has at least one special character
   */
  bool HasSpecial(const Password& pw) const;

  /**
   * @brief	    Check if at least one special character is selected
   * @return	true if at least one is checked
   */
  bool HasSpecialSelected() const;

  /**
   * @brief	    Generate a random password
   *
   * Generate a random password including at least one each of
   * uppercase, lowercase, number, and special character
   * 
   * @param	dst		    Destination password
   * @param	spcList	    List of specials to be used
   * @param	size	    Destination password size
   * @return	        0 on success, 1 on failure
   */
  int GenPW(Password& dst, const std::vector<bool>& spc_list, int pw_size);
};