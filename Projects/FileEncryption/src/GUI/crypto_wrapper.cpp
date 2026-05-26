/**
 * @file	crypto_wrapper.cpp
 * @brief	Implementation of CryptoWrapper class
 * @author	Astatine387
 */

#include "GUI/crypto_wrapper.h"

CryptoWrapper::CryptoWrapper(FILE* src, FILE* dst, const QString& dst_path, const Password& pw, CryptoMode mode)
    : worker_(src, dst, dst_path.toStdString(), pw, mode) {
  worker_.SetProgressCallback(
      [this](int perc, const std::string& s) { emit ProgressUpdate(perc, QString::fromStdString(s)); });

  worker_.SetFinishedCallback(
      [this](const std::string& msg, bool del) { emit Finished(QString::fromStdString(msg), del); });
}

void CryptoWrapper::Run() {
  worker_.Work();
}

void CryptoWrapper::RequestCancel() {
  worker_.RequestCancel();
}