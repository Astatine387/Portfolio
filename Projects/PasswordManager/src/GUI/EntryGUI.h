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
	explicit EntryGUI(QWidget *parent = nullptr);

	/**
	 * @brief	Set dialog to add mode
	 */
	void setAddMode();

	/**
	 * @brief	Set dialog to edit mode with existing data
	 * @param	site	Current site name
	 * @param	acc		Current account
	 * @param	pw		Current password
	 */
	void setEditMode(const std::string &site, const std::string &acc, const Password &pw);

	/**
	 * @brief	Get the entry input from the dialog
	 * @return	Entry input parameters
	 */
	Entry getInput();

private slots:
	/**
	 * @brief	Validate input and accept dialog
	 */
	void onOKClicked();

	/**
	 * @brief	Validate special character selection and emit generate request
	 */
	void onGenerateClicked();

	/**
	 * @brief	Check all special character checkboxes
	 */
	void onCheckAllClicked();

	/**
	 * @brief	Uncheck all special character checkboxes
	 */
	void onUncheckAllClicked();

	/**
	 * @brief	Reset special character checkboxes to default
	 */
	void onResetClicked();

private:
	PWLineEdit *pwLine; 
	QCheckBox *spcChecks[32];
	QGridLayout *spcGrid;
	QLabel *errMsg, *lenLabel;
	QLineEdit *siteLine, *accLine;
	QPushButton *checkAllBtn, *uncheckAllBtn, *resetBtn, *genBtn, *okBtn, *cancelBtn;
	QSlider *lenSlider;
	QHBoxLayout *btnBox, *lenBox, *spcBtnBox;
	QVBoxLayout *vBox;

	static constexpr char spcs[] = "`~!@#$%^&*()-_=+[{]}\\|;:\'\",<.>/?";

	static constexpr bool defaultSpc[32] = {
	//  `  ~  !  @  #  $  %  ^
		0, 1, 1, 1, 0, 0, 1, 1, 
	//  &  *  (  )  -  _  =  +
		0, 0, 0, 0, 0, 1, 1, 1,
	//  [  {  ]  }  \  |  ;  :
		1, 1, 1, 1, 0, 0, 0, 1,
	//  '  "  ,  <  .  >  /  ?
		0, 0, 1, 0, 0, 0, 0, 1
	};

	/**
	 * @brief	Get the special character selection list
	 * @return	Special character selection list
	 */
	std::vector<bool> getSpecialsList();

	bool hasSpecial(const Password &pw) const;

	/**
	 * @brief	Check if at least one special character is selected
	 * @return	true if at least one is checked
	 */
	bool hasSpecialSelected() const;

	/**
	 * @brief	Generate a random password
	 *
	 * Generate a random password including at least one each of
	 * uppercase, lowercase, number, and special character
	 * @param	dst		Destination password
	 * @param	spcList	List of specials to be used
	 * @param	size	Destination password size
	 * @return	0 on success, 1 on failure
	 */
	int genPW(Password &dst, const std::vector<bool> &spcList, int size);
};