/**
 * @file	crypto_wrapper.cpp
 * @brief	Implementation of CryptoWrapper class
 * @author	Astatine387
 */

#include "gui/crypto_wrapper.h"

CryptoWrapper::CryptoWrapper(const QString& src_path, const QString& dst_path, const Password& pw, CryptoMode mode)
    : worker_(src_path.toStdString(), dst_path.toStdString(), pw, mode) {
  worker_.SetProgressCallback(
      [this](int perc, const std::string& s) { emit ProgressUpdate(perc, QString::fromStdString(s)); });

  worker_.SetFinishedCallback([this](const std::string& msg) { emit Finished(QString::fromStdString(msg)); });
}

void CryptoWrapper::Run() {
  worker_.Work();
}

void CryptoWrapper::RequestCancel() {
  worker_.RequestCancel();
}