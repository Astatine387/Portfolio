/**
 * @file    crypto_wrapper.cpp
 * @brief   Implementation of CryptoWrapper class
 * @author  Astatine387
 */

#include "gui/crypto_wrapper.h"

#include <utility>

CryptoWrapper::CryptoWrapper(const QString& src_path, const QString& dst_path,
                             Password&& pw, CryptoMode mode,
                             CryptoWorker::CancelFlag cancel)
    : worker_(src_path.toStdString(), dst_path.toStdString(), std::move(pw),
              mode, std::move(cancel)) {
  /* Set CryptoWorker callbacks */

  worker_.SetProgressCallback([this](int perc, const std::string& s) {
    emit ProgressUpdate(perc, QString::fromStdString(s));
  });

  worker_.SetFinishedCallback([this](const std::string& msg) {
    emit Finished(QString::fromStdString(msg));
  });

  worker_.SetPhaseCallback([this](WorkPhase phase, const std::string& status) {
    emit PhaseChanged(QString::fromStdString(status),
                      IsCancellablePhase(phase));
  });
}

void CryptoWrapper::Run() {
  /* Enter the worker thread through QThread:started and blocks until the whole
   * file is done. This is a different thread, so the GUI stays responsive. */

  worker_.Work();
}
