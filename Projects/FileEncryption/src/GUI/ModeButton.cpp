/**
 * @file	ModeButton.cpp
 * @brief	Implementation of ModeButton class
 * @author	Astatine387
 */

#include "ModeButton.h"

ModeButton::ModeButton(QWidget *parent) : QWidget(parent) {
    /* Create layout and components */

    hBox = new QHBoxLayout;
    encBtn = new QRadioButton("Encrypt");
    decBtn = new QRadioButton("Decrypt");


    /* Neither is selected by default */

    encBtn->setChecked(false);
    decBtn->setChecked(false);


    /* Group buttons for mutual exclustion */

    btnGrp = new QButtonGroup(this);
    btnGrp->addButton(encBtn, 0);
    btnGrp->addButton(decBtn, 1);
    btnGrp->setExclusive(true);


    /* Configure layout */

    hBox->addWidget(encBtn);
    hBox->addWidget(decBtn);
    hBox->addStretch();
    hBox->setSpacing(10);
    hBox->setContentsMargins(0, 0, 0, 0);


    setLayout(hBox);
}

int ModeButton::getMode() {
    QAbstractButton *btn = btnGrp->checkedButton();
    return btn ? btnGrp->id(btn) : -1;
}