/**
 * @file	login_gui.h
 * @brief	Login window for vault file selection
 * @author	Astatine387
 */

#pragma once

#include <QHBoxLayout>
#include <QPushButton>
#include <QString>
#include <QWidget>

#include "Common/constants.h"

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
  explicit LoginGUI(QWidget* parent = nullptr);

 signals:
  /**
   * @brief	Signal when vault file is selected
   * @param	mode	0 for new, 1 for open
   * @param	path	Selected vault file path
   */
  void VaultSelected(VaultAction action, const QString& path);

 private slots:
  /**
   * @brief	Open file dialog for new vault creation
   */
  void OnNewClicked();

  /**
   * @brief	Open file dialog for existing vault
   */
  void OnOpenClicked();

 private:
  QPushButton* new_btn_;
  QPushButton* open_btn_;
  QHBoxLayout* hbox_;
};