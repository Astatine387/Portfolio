/**
 * @file	crypto_worker.h
 * @brief	Worker class for asynchronous encryption/decryption
 * @author	Astatine387
 */

#pragma once

#include <atomic>
#include <functional>
#include <memory>
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
   * @brief	Cancellation flag shared with whoever may request a cancel
   *
   * Shared rather than owned so that the canceller and the worker can be let go of in either order:
   * the flag outlives both, and neither has to know whether the other is still there.
   */
  using CancelFlag = std::shared_ptr<std::atomic<bool>>;

  /**
   * @brief	Constructor for CryptoWorker class
   * @param     src_path    Source file path
   * @param     dst_path    Destination file path
   * @param     pw          Password
   * @param     mode        Encryption/decryption mode
   * @param     cancel      Shared cancellation flag, or nullptr to own a private one
   *
   * A private flag when the caller supplies none, so polling always has something to read whether or
   * not anyone is in a position to raise it.
   */
  CryptoWorker(std::string src_path, std::string dst_path, Password pw, CryptoMode mode, CancelFlag cancel = nullptr)
      : mode_(mode),
        src_path_(std::move(src_path)),
        dst_path_(std::move(dst_path)),
        pw_(std::move(pw)),
        cancel_(cancel ? std::move(cancel) : std::make_shared<std::atomic<bool>>(false)) {}

  CryptoWorker(const CryptoWorker&) = delete;             // Delete copy constructor
  CryptoWorker& operator=(const CryptoWorker&) = delete;  // Delete copy assignment operator
  CryptoWorker(CryptoWorker&&) = delete;                  // Delete move constructor
  CryptoWorker& operator=(CryptoWorker&&) = delete;       // Delete move assignment operator

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
   * @brief		Callback function for entering a new phase
   * @param     phase   Phase the run has entered
   * @param     status  Message describing what the run is doing now
   *
   * Separate from the progress callback because a phase says what a percentage cannot: two of the three
   * phases have no percentage to report and no cancellation to offer, and saying so is what keeps a
   * long pause from reading as a hang.
   */
  using PhaseCallback = std::function<void(WorkPhase phase, const std::string& status)>;

  /**
   * @brief   Cancel the process
   *
   * Safe to call from any thread and at any point in the worker's lifetime.
   */
  void RequestCancel();

  /**
   * @brief   Perform encryption/decryption
   *
   * Runs the whole file to completion on the calling thread. Cancellation is only looked at between
   * chunks, so a call already under way cannot be made to return at once.
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

  /**
   * @brief		Set phase callback function
   * @param		phcb	Phase callback function
   */
  void SetPhaseCallback(PhaseCallback phcb) { phcb_ = std::move(phcb); }

 private:
  CryptoMode mode_;
  std::string src_path_, dst_path_;
  Password pw_;
  CancelFlag cancel_;
  ProgressCallback pcb_;
  FinishedCallback fcb_;
  PhaseCallback phcb_;

  /* Filled by the engine's error callback and read once the pass is over, so the line that explains a
   * failure outlives the call that produced it and can be put in front of the summary */

  std::string err_;

  /**
   * @brief   Poll the cancellation flag
   * @return  true if the user requested cancellation
   */
  [[nodiscard]] bool IsCancelled() const { return cancel_->load(std::memory_order_relaxed); }

  /**
   * @brief   Report the phase the run has entered
   * @param   phase   Phase entered
   * @param   status  Message describing what the run is doing now
   *
   * Announced on entry rather than on exit: the point of a phase report is to describe a wait that has
   * not happened yet.
   */
  void ReportPhase(WorkPhase phase, const std::string& status);
};
