/**
 * @file	worker.h
 * @brief	Worker class for asynchronous encryption/decryption
 * @author	Astatine387
 */

#pragma once

#include <QObject>
#include <QString>

#include "Core/aes_gcm.h"
#include "Utils/password.h"

/**
 * @class	Worker
 * @brief	Worker class for asynchronous encryption/decryption
 */
class Worker : public QObject {
  Q_OBJECT

 public:
  /**
   * @brief	Constructor for Worker class
   * @param   srcFile     Source file
   * @param   dstFile     Destination file
   * @param   dstPath     Destination file path
   * @param   pw          Password
   * @param   mode        Encryption/decryption mode
   */
  Worker(FILE* src_file, FILE* dst_file, const QString& dst_path,
         const Password& pw, int mode)
      : src_file_(src_file),
        dst_file_(dst_file),
        dst_path_(dst_path),
        pw_(pw),
        mode_(mode) {}

 signals:
  /**
   * @brief	Signal when encryption/decryption is completed
   * @param   msg             Result message
   * @param   shouldDelete    Destination file deletion flag value
   */
  void Finished(QString msg, bool should_delete);

  /**
   * @brief   Update progress bar and status message
   * @param   perc     Progress percentage
   * @param   status  Status message
   */
  void ProgressUpdate(int perc, QString status);

 public slots:
  /**
   * @brief   Cancel the process
   */
  void RequestCancel();

  /**
   * @brief   Perform encryption/decryption
   */
  void Work();

 private:
  FILE *src_file_ = nullptr, *dst_file_ = nullptr;
  QString err_ = "", dst_path_;
  Password pw_;
  std::atomic<bool> should_cancel_{ false };
  int mode_;
};