/**
 * @file	PWLineEdit.h
 * @brief	Password input window with show/hide toggle
 * @author	Astatine387
 */

#pragma once

#include "Utils/Password.h"
#include <QHBoxLayout>
#include <QLineEdit>
#include <QPushButton>
#include <QWidget>

/**
 * @class   PWLineEdit
 * @brief   Password input window with show/hide toggle
 */
class PWLineEdit : public QWidget {
    Q_OBJECT

public:
    /**
     * @brief   Constructor of PWLineEdit class
     * @param   parent  Parent widget
     */
    explicit PWLineEdit(QWidget *parent = nullptr);

    /**
     * @brief   Clear the input field
     */
    void clear();

    /**
     * @brief   Extract data from the input line to Password class
     * @param   pw  Destination
     */
    void extract(Password &pw);

private slots:
    /**
     * @brief   Signal when toggle masking button clicked
     */
    void toggleMask();

private:
    QHBoxLayout *hBox;
    QLineEdit *pwLine;
    QPushButton *maskBtn;
};