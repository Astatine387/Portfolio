/**
 * @file	Worker.h
 * @brief	Worker class for asynchronous encryption/decryption
 * @author	Astatine387
 */

#pragma once

#include "Core/AES_GCM.h"
#include "Utils/Password.h"

#include <QObject>
#include <QString>

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
    Worker(FILE *srcFile, FILE *dstFile, const QString &dstPath, const Password &pw, int mode) {
        this->srcFile = srcFile;
        this->dstFile = dstFile;
        this->dstPath = dstPath;
        this->pw.setData(pw);
        this->mode = mode;
    }

signals:
    /**
     * @brief	Signal when encryption/decryption is completed
     * @param   msg             Result message
     * @param   shouldDelete    Destination file deletion flag value
     */
    void finished(QString msg, bool shouldDelete);

    /**
     * @brief   Update progress bar and status message
     * @param   perc     Progress percentage
     * @param   status  Status message
     */
    void progressUpdate(int perc, QString status);

public slots:
    /**
     * @brief   Cancel the process
     */
    void requestCancel();

    /**
     * @brief   Perform encryption/decryption
     */
    void work();

private:
    FILE *srcFile = nullptr, *dstFile = nullptr;
    QString err = "", dstPath;
    Password pw;
    std::atomic<bool> shouldCancel{ false };
    int mode;
};