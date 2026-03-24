/**
 * @file	main.cpp
 * @brief	Entry point of the application
 * @author	Astatine387
 */

#include "GUI/MainGUI.h"
#include <QApplication>
#include <QFont>
#include <QRect>
#include <QScreen>
#include <QSize>

int ShowGUI(int argc, char *argv[]) {
    QApplication app(argc, argv);
    MainGUI *gui = new MainGUI;


    /* Configure font size */

    QFont font;
    font.setPointSizeF(font.pointSizeF() * kFontScale);
    QApplication::setFont(font);


    /* Configure window size */

    QSize qsize(300, 150);
    gui->resize(qsize);


    /* Configure window position */

    QScreen *screen = QGuiApplication::primaryScreen();
    QRect rect = screen->availableGeometry();

    int x = (rect.width() - gui->width()) / 2;
    int y = (rect.height() - gui->height()) / 2 - 50;

    gui->move(x, y);

    gui->show();


    return app.exec();
}

int main(int argc, char *argv[]) {
    return ShowGUI(argc, argv);
}