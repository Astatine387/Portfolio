/**
 * @file    mutex.h
 * @brief   Thread safety annotated wrappers around the standard mutex
 * @author  Astatine387
 */

#pragma once

#include <condition_variable>
#include <mutex>

#include "utils/thread_annotations.h"

/**
 * @brief   std::mutex carrying the capability annotation the analysis needs
 */
class CAPABILITY("mutex") Mutex {
 public:
  /**
   * @brief   Default constructor of Mutex
   */
  Mutex() = default;

  Mutex(const Mutex&) = delete;
  Mutex& operator=(const Mutex&) = delete;

  /**
   * @brief   Acquire the mutex, blocking until it is available
   */
  void Lock() ACQUIRE() { mtx_.lock(); }

  /**
   * @brief   Release the mutex
   */
  void Unlock() RELEASE() { mtx_.unlock(); }

  /**
   * @brief   Expose the wrapped mutex so a lock can be built on it
   * @return  Reference to the underlying std::mutex
   */
  std::mutex& Native() { return mtx_; }

 private:
  std::mutex mtx_;  // Wrapped standard mutex
};

/**
 * @brief   Scoped lock owning a real std::unique_lock
 */
class SCOPED_CAPABILITY UniqueLock {
 public:
  /**
   * @brief   Acquire a mutex
   * @param   m   Mutex to acquire
   */
  explicit UniqueLock(Mutex& m) ACQUIRE(m) : lk_(m.Native()) {}

  /**
   * @brief   Destructor of UniqueLock, release the mutex
   */
  ~UniqueLock() RELEASE() = default;

  UniqueLock(const UniqueLock&) = delete;
  UniqueLock& operator=(const UniqueLock&) = delete;

  /**
   * @brief   Re-acquire the mutex
   */
  void Lock() ACQUIRE() { lk_.lock(); }

  /**
   * @brief   Release the mutex
   */
  void Unlock() RELEASE() { lk_.unlock(); }

  /**
   * @brief   Expose the wrapped lock so a condition variable can wait on it
   * @return  Reference to the underlying std::unique_lock
   */
  std::unique_lock<std::mutex>& Native() { return lk_; }

 private:
  std::unique_lock<std::mutex> lk_;
};

/**
 * @brief   std::condition_variable waiting through the annotated UniqueLock
 */
class ConditionVariable {
 public:
  /**
   * @brief   Block until the predicate holds, releasing the lock while waiting
   * @param   lk  Lock held by the caller
   * @param   p   Predicate, only ever evaluated with the lock held
   */
  template <typename Pred>
  void Wait(UniqueLock& lk, Pred p) {
    cv_.wait(lk.Native(), p);
  }

  /**
   * @brief   Wake one thread waiting on the condition variable
   */
  void NotifyOne() { cv_.notify_one(); }

 private:
  std::condition_variable cv_;
};
