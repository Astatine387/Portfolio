/**
 * @file	ProgressGUI.h
 * @brief	Progress bar widget with cancel and close buttons
 * @author	Astatine387
 */

#pragma once

#include <QHBoxLayout>
#include <QLabel>
#include <QProgressBar>
#include <QPushButton>
#include <QVBoxLayout>
#include <QWidget>

/**
 * @class	ProgressGUI
 * @brief	Progress bar widget with cancel and close buttons
 */
class ProgressGUI : public QWidget {
    Q_OBJECT

public:
    /**
     * @brief   Constructor of ProgressGUI class
     * @param   parent  Parent widget
     */
    explicit ProgressGUI(QWidget *parent = nullptr);

    /**
     * @brief   Check whether the process is cancelled by user
     * @return  true if cancel button is clicked
     */
    bool isCancelled();

    /**
     * @brief   Update progress bar and status message
     * @param   perc     Progress percentage
     * @param   status  Status message
     */
    void update(int perc, const QString &status);

    /**
     * @brief   Show result and enable close button
     * @param   msg     result message
     */
    void showResult(const QString &msg);

signals:
    /**
     * @brief   Signal when cancel button clicked
     */
    void cancelRequested();

    /**
     * @brief   Signal when close button clicked
     */
    void closeRequested();

private slots:
    /**
     * @brief   Set cancellation flag and emit cancellation signal
     */
    void onCancelClicked();

private:
    QLabel *prgLabel;
    QProgressBar *prgBar;
    QPushButton *cancelBtn, *closeBtn;
    QHBoxLayout *hBox;
    QVBoxLayout *vBox;
    bool cancelled = false;
};