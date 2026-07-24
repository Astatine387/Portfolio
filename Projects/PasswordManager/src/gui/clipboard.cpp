/**
 * @file	clipboard.cpp
 * @brief	Implementation of clipboard helper functions
 * @author	Astatine387
 */

#include "gui/clipboard.h"

#include <QByteArray>
#include <QClipboard>
#include <QGuiApplication>
#include <QMimeData>
#include <QString>

namespace clipboard {

void SetSecret(const Password& pw) {
  /* QClipboard takes ownership of the QMimeData */

  QMimeData* mime = new QMimeData;

  mime->setText(QString::fromUtf8(pw.GetData(), static_cast<int>(pw.GetSize())));

#ifdef Q_OS_WIN
  mime->setData("ExcludeClipboardContentFromMonitorProcessing", QByteArray(1, 1));
  mime->setData("CanIncludeInClipboardHistory", QByteArray(4, '\0'));
  mime->setData("CanUploadToCloudClipboard", QByteArray(4, '\0'));

#else
  mime->setData("x-kde-passwordManagerHint", QByteArray("secret"));

#endif
  QGuiApplication::clipboard()->setMimeData(mime);
}

bool ClearIfOwned() {
  QClipboard* board = QGuiApplication::clipboard();

  /* If another application has taken the clipboard, do not clear it */

  if (!board->ownsClipboard()) {
    return false;
  }

  board->clear();

  return true;
}

}  // namespace clipboard
