/**
 * @file	crypto_wrapper.h
 * @brief	Qt wrapper class for CryptoWorker
 * @author	Astatine387
 */

#pragma once

#include <QObject>
#include <QString>

#include "Common/constants.h"
#include "Core/crypto_worker.h"

class CryptoWrapper : public QObject {
  Q_OBJECT

 public:
  /**
   * @brief	Constructor for CryptoWorker class
   * @param     src_file    Source file
   * @param     dst_file    Destination file
   * @param     dst_path    Destination file path
   * @param     pw          Password
   * @param     mode        Encryption/decryption mode
   */
  CryptoWrapper(FILE* src, FILE* dst, const QString& dst_path, const Password& pw, CryptoMode mode);

 signals:
  /**
   * @brief	Signal when encryption/decryption is completed
   * @param   msg             Result message
   * @param   should_delete     Destination file deletion flag value
   */
  void Finished(const QString& msg, bool should_delete);

  /**
   * @brief   Update progress bar and status message
   * @param   perc     Progress percentage
   * @param   status  Status message
   */
  void ProgressUpdate(int perc, const QString& status);

 public slots:
  /**
   * @brief   Cancel the process
   */
  void RequestCancel();

  /**
   * @brief   Perform encryption/decryption
   */
  void Run();

 private:
  CryptoWorker worker_;
};