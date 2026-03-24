/**
 * @file	LoginGUI.h
 * @brief	Login window for vault file selection
 * @author	Astatine387
 */

#pragma once

#include <QHBoxLayout>
#include <QPushButton>
#include <QString>
#include <QWidget>

/**
 * @class	LoginGUI
 * @brief	Login window for vault file selection
 */
class LoginGUI : public QWidget {
	Q_OBJECT

public:
	/**
	 * @brief	Constructor of LoginGUI class
	 * @param	parent	Parent widget
	 */
	explicit LoginGUI(QWidget *parent = nullptr);

signals:
	/**
	 * @brief	Signal when vault file is selected
	 * @param	mode	0 for new, 1 for open
	 * @param	path	Selected vault file path
	 */
	void vaultSelected(int mode, const QString &path);

private slots:
	/**
	 * @brief	Open file dialog for new vault creation
	 */
	void onNewClicked();

	/**
	 * @brief	Open file dialog for existing vault
	 */
	void onOpenClicked();

private:
	QPushButton *newBtn;
	QPushButton *openBtn;
	QHBoxLayout *hBox;
};