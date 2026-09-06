/**
 * @file	crypto_wrapper.h
 * @brief	Qt wrapper class for CryptoWorker
 * @author	Astatine387
 */

#pragma once

#include <QObject>
#include <QString>

#include "common/constants.h"
#include "core/crypto_worker.h"

/**
 * @class   CryptoWrapper
 * @brief   Qt wrapper class for CryptoWorker
 *
 * The one Qt-aware layer over the worker. CryptoWorker reports through plain callbacks and knows nothing
 * about Qt, which is what lets the core be built and tested without an event loop; this object turns
 * those callbacks into signals and is moved to the worker thread, so the connections to the window
 * become queued ones.
 */
class CryptoWrapper : public QObject {
  Q_OBJECT

 public:
  /**
   * @brief	Constructor for CryptoWrapper class
   * @param		src_path	Source file path
   * @param		dst_path	Destination file path
   * @param		pw			Password, moved into the worker
   * @param		mode		Encryption/decryption mode
   * @param		cancel		Cancellation flag shared with the caller
   */
  CryptoWrapper(const QString& src_path, const QString& dst_path, Password&& pw, CryptoMode mode,
                CryptoWorker::CancelFlag cancel);

 signals:
  /**
   * @brief		Signal when encryption/decryption is completed
   * @param		msg		Result message
   */
  void Finished(const QString& msg);

  /**
   * @brief		Update progress bar and status message
   * @param		perc	Progress percentage
   * @param		status	Status message
   */
  void ProgressUpdate(int perc, const QString& status);

 public slots:
  /**
   * @brief		Perform encryption/decryption
   */
  void Run();

 private:
  CryptoWorker worker_;  // Held by value, so it is destroyed with the wrapper on the worker thread
};
