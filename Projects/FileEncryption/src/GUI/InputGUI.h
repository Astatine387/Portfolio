/**
 * @file	InputGUI.h
 * @brief	User input window with start button
 * @author	Astatine387
 */

#pragma once

#include "GUI/ModeButton.h"
#include "GUI/PWLineEdit.h"
#include "Utils/Password.h"

#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>
#include <QWidget>

/**
  * @struct     UserInput
  * @brief      Container for user input parameters
  */
struct UserInput {
    bool valid = false;
    int mode = -1;
    QString src;
    QString dst;
    Password pw;
};

/**
 * @class   InputGUI
 * @brief   User input window with start button
 */
class InputGUI : public QWidget {
    Q_OBJECT

public:
    /**
     * @brief   Constructor of InputGUI class
     * @param   parent  Parent widget
     */
    explicit InputGUI(QWidget *parent = nullptr);

    /**
     * @brief   Display error message
     * @param   msg     error message string
     */
    void setErrMsg(const QString &msg);

signals:
    /**
     * @brief   Signal when start button clicked
     * @param   input   User inputs
     */
    void startRequested(const UserInput &input);

private slots:
    /**
     * @brief   Check the user input parameters are valid and start process
     */
    void onStartClicked();

private:
    ModeButton *modeBtn;
    PWLineEdit *pwLine;
    QLineEdit *srcLine;     // Source file input field
    QLineEdit *dstLine;     // Destination file input field
    QPushButton *startBtn;
    QLabel *errMsg;         // Label to display error messages
    QHBoxLayout *hBox;      // Layout for start button and error message
    QVBoxLayout *vBox;
};