/**
 * @file	InputGUI.cpp
 * @brief	Implementation of InputGUI class
 * @author	Astatine387
 */

#include "InputGUI.h"

InputGUI::InputGUI(QWidget *parent) : QWidget(parent) {
    /* Create layouts and components */

    modeBtn = new ModeButton;
    srcLine = new QLineEdit;
    dstLine = new QLineEdit;
    pwLine = new PWLineEdit;
    startBtn = new QPushButton("Start");
    errMsg = new QLabel;
    hBox = new QHBoxLayout;
    vBox = new QVBoxLayout;


    /* Set placeholder text that indicates each field */

    srcLine->setPlaceholderText("Source File");
    dstLine->setPlaceholderText("Destination File");


    /* Put start button and error message in the same line */

    hBox->addWidget(startBtn);
    hBox->addWidget(errMsg);
    hBox->addStretch();
    hBox->setSpacing(10);
    hBox->setContentsMargins(0, 0, 0, 0);


    /* Configure main layout */

    vBox->addWidget(modeBtn);
    vBox->addWidget(srcLine);
    vBox->addWidget(dstLine);
    vBox->addWidget(pwLine);
    vBox->addLayout(hBox);
    vBox->addStretch();
    vBox->setSpacing(10);
    vBox->setContentsMargins(10, 10, 10, 10);

    setLayout(vBox);


    /* Connect encryption/decryption start function to button */

    connect(startBtn, &QPushButton::clicked, this, &InputGUI::onStartClicked);
}

void InputGUI::setErrMsg(const QString &msg) {
    errMsg->setText(msg);
}

void InputGUI::onStartClicked() {
    UserInput input;

    if ((input.mode = modeBtn->getMode()) == -1) {
        errMsg->setText("Mode is not selected");
        return;
    }

    if ((input.src = srcLine->text()).isEmpty()) {
        errMsg->setText("Source file is not input");
        return;
    }

    if ((input.dst = dstLine->text()).isEmpty()) {
        errMsg->setText("Destination file is not input");
        return;
    }

    pwLine->extract(input.pw);

    if (input.pw.isEmpty()) {
        errMsg->setText("Password is not input");
        return;
    }

    pwLine->clear();

    input.valid = true;

    emit startRequested(input);
}