/**
 * @file	crypto_worker.h
 * @brief	Worker class for asynchronous encryption/decryption
 * @author	Astatine387
 */

#pragma once

#include <atomic>
#include <functional>
#include <string>

#include "common/constants.h"
#include "core/aes_gcm.h"
#include "utils/password.h"

/**
 * @class	CryptoWorker
 * @brief	Worker class for asynchronous encryption/decryption
 */
class CryptoWorker {
 public:
  /**
   * @brief	Constructor for CryptoWorker class
   * @param     src_path    Source file path
   * @param     dst_path    Destination file path
   * @param     pw          Password
   * @param     mode        Encryption/decryption mode
   */
  CryptoWorker(std::string src_path, std::string dst_path, Password pw, CryptoMode mode)
      : mode_(mode), src_path_(std::move(src_path)), dst_path_(std::move(dst_path)), pw_(std::move(pw)) {}

  /**
   * @brief		Callback function for progress reporting
   * @param     perc    Progress percentage
   * @param     status  Status message
   */
  using ProgressCallback = std::function<void(int perc, const std::string& status)>;

  /**
   * @brief		Callback function for job finished
   * @param		msg             Result message
   */
  using FinishedCallback = std::function<void(const std::string& msg)>;

  /**
   * @brief     Cancel the process
   */
  void RequestCancel();

  /**
   * @brief     Perform encryption/decryption
   */
  void Work();

  /**
   * @brief		Set progress callback function
   * @param		pcb		Progress callback function
   */
  void SetProgressCallback(ProgressCallback pcb) { pcb_ = std::move(pcb); }

  /**
   * @brief		Set finished callback function
   * @param		fcb		Finished callback function
   */
  void SetFinishedCallback(FinishedCallback fcb) { fcb_ = std::move(fcb); }

 private:
  CryptoMode mode_;
  std::string src_path_, dst_path_;
  Password pw_;
  std::atomic<bool> should_cancel_{ false };
  ProgressCallback pcb_;
  FinishedCallback fcb_;
  std::string err_;
};
