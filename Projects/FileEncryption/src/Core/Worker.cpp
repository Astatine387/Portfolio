/**
 * @file	Worker.cpp
 * @brief	Implementation of Worker class
 * @author	Astatine387
 */

#include "Worker.h"

void Worker::requestCancel() {
    shouldCancel.store(true, std::memory_order_release);
}

void Worker::work() {
    AES_GCM aes;
    QString msg;
    bool shouldDelete = false;
    int res;

    aes.setErrorCb([this](const char *msg) {
        err = QString(msg);
        });

    aes.setProgressCb([this](int perc, bool *cancelled) {
        QString status;

        if (mode == 0) {
            status = QString("Encrypting... %1%\n").arg(perc);
        }
        else {
            status = QString("Decrypting... %1%\n").arg(perc);
        }

        emit progressUpdate(perc, status);

        *cancelled = shouldCancel.load(std::memory_order_acquire);
        });

    if (mode == 0) {
        res = aes.encrypt(srcFile, dstFile, pw.getData(), pw.getSize());

        if (shouldCancel) {
            msg = "Encryption canceled\n";
            shouldDelete = true;
        }
        else if (res) {
            msg = err + "Encryption failed\n";
            shouldDelete = true;
        }
        else {
            msg = "Encryption complete\n";
        }
    }
    else {
        res = aes.decrypt(srcFile, dstFile, pw.getData(), pw.getSize());

        if (shouldCancel) {
            msg = "Decryption canceled\n";
            shouldDelete = true;
        }
        else if (res) {
            msg = err + "Decryption failed\n";
            shouldDelete = true;
        }
        else {
            msg = "Decryption complete\n";
        }
    }

    emit finished(msg, shouldDelete);
}