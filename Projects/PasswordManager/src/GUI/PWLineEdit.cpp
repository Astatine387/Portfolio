/**
 * @file	PWLineEdit.cpp
 * @brief	Implementation of PWLineEdit class
 * @author	Astatine387
 */

#include "GUI/PWLineEdit.h"
#include "Utils/library.h"

PWLineEdit::PWLineEdit(QWidget *parent) : QWidget(parent) {
    /* Create layout and components */

    hBox = new QHBoxLayout;
    maskBtn = new QPushButton("See");
    pwLine = new QLineEdit;


    /* Configure input line */

    pwLine->setPlaceholderText("Password");
    pwLine->setMaxLength(kMaxPWLen);
    pwLine->setEchoMode(QLineEdit::Password);


    /* Configure masking toggle button */

    maskBtn->setFixedSize(static_cast<int>(45 * kFontScale), static_cast<int>(pwLine->sizeHint().height() * kFontScale));


    /* Configure layout */

    hBox->addWidget(pwLine);
    hBox->addWidget(maskBtn);
    hBox->setSpacing(10);
    hBox->setContentsMargins(0, 0, 0, 0);


    /* Connect masking toggle function to button */

    connect(maskBtn, &QPushButton::clicked, this, &PWLineEdit::toggleMask);


    setLayout(hBox);
}

int PWLineEdit::extract(Password &pw) {
    QByteArray data = pwLine->text().toUtf8();
    int size = data.size(), res;

    Lock(data.data(), size);

    res = pw.setData(data.constData(), size);

    Wipe(data.data(), size);
    Unlock(data.data(), size);

    pwLine->clear();

    return res;
}

void PWLineEdit::clear() {
    pwLine->clear();
}

void PWLineEdit::setPassword(const Password &pw) {
    if (!pw.isEmpty()) {
        pwLine->setText(QString::fromUtf8(pw.getData(), static_cast<int>(pw.getSize())));
    }
}

void PWLineEdit::toggleMask() {
    if (pwLine->echoMode() == QLineEdit::Password) {
        pwLine->setEchoMode(QLineEdit::Normal);
        maskBtn->setText("Hide");
    }
    else {
        pwLine->setEchoMode(QLineEdit::Password);
        maskBtn->setText("See");
    }
}