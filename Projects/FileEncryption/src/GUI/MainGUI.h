/**
 * @file	MainGUI.h
 * @brief	Main GUI class that controls entire workflow
 * @author	Astatine387
 */

#pragma once

#include "Core/Worker.h"
#include "GUI/InputGUI.h"
#include "GUI/ProgressGUI.h"
#include <QStackedWidget>
#include <QThread>
#include <QVBoxLayout>
#include <QWidget>

/**
 * @class   MainGUI
 * @brief   Main GUI class that orchestrates entire workflow
 */
class MainGUI : public QWidget {
    Q_OBJECT

public:
    /**
     * @brief   Constructor of MainGUI class
     * @param   parent  Parent widget
     */
    explicit MainGUI(QWidget *parent = nullptr);

    /**
     * @brief	Destructor of MainGUI class
     */
    ~MainGUI();

    /**
     * @brief   Get the current user input
     * @return  Current user input
     */
    UserInput getUserInput();

    /**
     * @brief   Check the current user input is valid
     * @return  true if valid
     */
    bool isInputValid();

private slots:
    /**
     * @brief	Start encryption/decryption process
     * @param   input   User input parameters
     */
    void onStartRequested(const UserInput &input);

    /**
     * @brief	Update progress bar and status message
     * @param   perc    Progress percentage
     * @param   status  Status message
     */
    void onProgressUpdated(int perc, const QString &status);

    /**
     * @brief	Show result and set deletion flag
     * @param   msg             Result message
     * @param   shouldDelete    Destination file deletion flag value
     */
    void onWorkFinished(const QString &msg, bool shouldDelete);

    /**
     * @brief	Clean resources on worker thread finished
     */
    void onThreadFinished();

    /**
     * @brief	Clean resources on close button clicked
     */
    void onCloseRequested();

private:
    FILE *srcFile = nullptr, *dstFile = nullptr;
    InputGUI *inputGUI;
    ProgressGUI *prgGUI;
    QStackedWidget *widget;
    QThread *thread;
    QVBoxLayout *vBox;
    UserInput userInput;
    Worker *worker;
    bool shouldDelete = false;  // Destination file deletion flag for cancellation or failure

    /**
     * @brief   Open file pointers
     * @return  0 on success, 1 on error
     */
    int openFiles();

    /**
     * @brief   Clean all resources
     */
    void clean();

    /**
     * @brief   Clean file pointers
     */
    void closeFiles();
};