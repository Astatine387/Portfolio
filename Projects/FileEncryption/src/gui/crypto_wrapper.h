/**
 * @file    crypto_wrapper.h
 * @brief   Qt wrapper class for CryptoWorker
 * @author  Astatine387
 */

#pragma once

#include <QObject>
#include <QString>

#include "common/constants.h"
#include "core/crypto_worker.h"

/**
 * @brief   Qt wrapper class for CryptoWorker
 */
class CryptoWrapper : public QObject {
  Q_OBJECT

 public:
  /**
   * @brief   Constructor for CryptoWrapper class
   * @param   src_path  Source file path
   * @param   dst_path  Destination file path
   * @param   pw        Password, moved into the worker
   * @param   mode      Encryption/decryption mode
   * @param   cancel    Cancellation flag shared with the caller
   */
  CryptoWrapper(const QString& src_path, const QString& dst_path, Password&& pw,
                CryptoMode mode, CryptoWorker::CancelFlag cancel);

 signals:
  /**
   * @brief   Signal when encryption/decryption is completed
   * @param   msg   Result message
   */
  void Finished(const QString& msg);

  /**
   * @brief   Update progress bar and status message
   * @param   perc    Progress percentage
   * @param   status  Status message
   */
  void ProgressUpdate(int perc, const QString& status);

  /**
   * @brief   Signal when the run enters a new phase
   * @param   status        Message describing what the run is doing now
   * @param   cancellable   Whether cancelling would end the run early
   *
   * Carries a bool rather than the phase itself. The window has no use for the
   * name of the phase, only for what it may still offer the user, and a bool
   * crosses a queued connection without asking the core layer to know what a Qt
   * meta-type is.
   */
  void PhaseChanged(const QString& status, bool cancellable);

 public slots:
  /**
   * @brief   Perform encryption/decryption
   */
  void Run();

 private:
  CryptoWorker worker_;
};
