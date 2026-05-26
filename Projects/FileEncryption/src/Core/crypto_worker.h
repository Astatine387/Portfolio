/**
 * @file	crypto_worker.h
 * @brief	Worker class for asynchronous encryption/decryption
 * @author	Astatine387
 */

#pragma once

#include <atomic>
#include <cstdio>
#include <functional>
#include <string>

#include "Common/constants.h"
#include "Core/aes_gcm.h"
#include "Utils/password.h"

/**
 * @class	CryptoWorker
 * @brief	Worker class for asynchronous encryption/decryption
 */
class CryptoWorker {
 public:
  /**
   * @brief	Constructor for CryptoWorker class
   * @param     src_file    Source file
   * @param     dst_file    Destination file
   * @param     dst_path    Destination file path
   * @param     pw          Password
   * @param     mode        Encryption/decryption mode
   */
  CryptoWorker(FILE* src_file, FILE* dst_file, const std::string& dst_path, const Password& pw, CryptoMode mode)
      : src_file_(src_file), dst_file_(dst_file), dst_path_(dst_path), pw_(pw), mode_(mode) {}

  /**
   * @brief		Callback function for progress reporting
   * @param     perc    Progress percentage
   * @param     status  Status message
   */
  using ProgressCallback = std::function<void(int perc, const std::string& status)>;

  /**
   * @brief		Callback function for job finished
   * @param		msg             Result message
   * @param		should_delete   Destination file deletion flag value
   */
  using FinishedCallback = std::function<void(const std::string& msg, bool should_delete)>;

  /**
   * @brief   Cancel the process
   */
  void RequestCancel();

  /**
   * @brief   Perform encryption/decryption
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
  FILE *src_file_ = nullptr, *dst_file_ = nullptr;
  std::string dst_path_;
  Password pw_;
  std::atomic<bool> should_cancel_{ false };
  ProgressCallback pcb_;
  FinishedCallback fcb_;
};