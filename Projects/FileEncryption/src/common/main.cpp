/**
 * @file	main.cpp
 * @brief	Entry point of the application
 * @author	Astatine387
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

  /* Scaling the size Qt already resolved, rather than setting one outright, so the platform's own font
   * setting still decides what the scale is applied to */

  QFont font;
  font.setPointSizeF(font.pointSizeF() * kFontScale);
  QApplication::setFont(font);

  QSize qsize(300, 150);
  gui.resize(qsize);

  /* availableGeometry rather than the full screen, so a taskbar or panel is excluded and the window is
   * centred in the space actually free. The offset lifts it above the true centre, where a window this
   * short otherwise reads as sitting low. */

  QScreen* screen = QGuiApplication::primaryScreen();
  QRect rect = screen->availableGeometry();

  int x = (rect.width() - gui.width()) / 2;
  int y = (rect.height() - gui.height()) / 2 - 50;

  gui.move(x, y);
  gui.show();

  return app.exec();
}

int main(int argc, char** argv) {
  /* The limit it raises is process-wide and best effort, so it is settled once here rather than from
   * whichever secure allocation happens to come first */

  InitCrypto();

  return ShowGUI(argc, argv);
}
