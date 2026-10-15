/**
 * @file    main.cpp
 * @brief   Application entry point
 * @author  Astatine387
 */

#include <QApplication>
#include <QFont>
#include <QRect>
#include <QScreen>
#include <QSize>

#include "core/secure_key.h"
#include "gui/main_gui.h"

int ShowGUI(int argc, char** argv) {
  QApplication app(argc, argv);
  MainGUI gui;

  /* Configure GUI font size */

  QFont font;
  font.setPointSizeF(font.pointSizeF() * kFontScale);
  QApplication::setFont(font);

  /* Configure GUI window size */

  QSize qsize(300, 150);
  gui.resize(qsize);

  /* Locate GUI in the center */

  QScreen* screen = QGuiApplication::primaryScreen();  // Use OS primary display
  QRect rect = screen->availableGeometry();  // Exclude the reserved area

  int x = (rect.width() - gui.width()) / 2;
  int y = (rect.height() - gui.height()) / 2 - 50;

  gui.move(x, y);
  gui.show();

  return app.exec();
}

int main(int argc, char** argv) {
  InitCrypto();

  return ShowGUI(argc, argv);
}
