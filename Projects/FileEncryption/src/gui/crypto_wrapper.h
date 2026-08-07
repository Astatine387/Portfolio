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

class CryptoWrapper : public QObject {
  Q_OBJECT

 public:
  /**
   * @brief	Constructor for CryptoWrapper class
   * @param		src_path	Source file path
   * @param		dst_path	Destination file path
   * @param		pw			Password, moved into the worker
   * @param		mode		Encryption/decryption mode
   */
  CryptoWrapper(const QString& src_path, const QString& dst_path, Password&& pw, CryptoMode mode);

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
   * @brief		Cancel the process
   */
  void RequestCancel();

  /**
   * @brief		Perform encryption/decryption
   */
  void Run();

 private:
  CryptoWorker worker_;
};
