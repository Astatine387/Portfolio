/**
 * @file	crypto_wrapper.cpp
 * @brief	Implementation of CryptoWrapper class
 * @author	Astatine387
 */

#include "gui/crypto_wrapper.h"

#include <utility>

CryptoWrapper::CryptoWrapper(const QString& src_path, const QString& dst_path, Password&& pw, CryptoMode mode,
                             CryptoWorker::CancelFlag cancel)
    : worker_(src_path.toStdString(), dst_path.toStdString(), std::move(pw), mode, std::move(cancel)) {
  worker_.SetProgressCallback(
      [this](int perc, const std::string& s) { emit ProgressUpdate(perc, QString::fromStdString(s)); });

  worker_.SetFinishedCallback([this](const std::string& msg) { emit Finished(QString::fromStdString(msg)); });
}

void CryptoWrapper::Run() {
  worker_.Work();
}
