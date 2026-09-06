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
  /* CryptoWorker is deliberately free of Qt and reports through plain callbacks. Re-emitting them as
   * signals is what carries a report across to the GUI thread: this object is moved to the worker
   * thread, so the connections to the window become queued ones and the strings are copied over. */

  worker_.SetProgressCallback(
      [this](int perc, const std::string& s) { emit ProgressUpdate(perc, QString::fromStdString(s)); });

  worker_.SetFinishedCallback([this](const std::string& msg) { emit Finished(QString::fromStdString(msg)); });

  /* Whether a phase can be cancelled is decided in the core, beside the code that polls the flag, so
   * the window is only told the answer and never has to work it out again */

  worker_.SetPhaseCallback([this](WorkPhase phase, const std::string& status) {
    emit PhaseChanged(QString::fromStdString(status), IsCancellablePhase(phase));
  });
}

void CryptoWrapper::Run() {
  /* Entered on the worker thread through QThread::started and blocks until the whole file is done. The
   * window stays responsive because this is a different thread, not because the work yields. */

  worker_.Work();
}
