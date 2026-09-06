/**
 * @file	mutex.h
 * @brief	Thread safety annotated wrappers around the standard locking primitives
 * @author	Astatine387
 *
 * The analysis can only reason about types that carry a capability, and the standard ones carry none.
 * These wrappers exist to attach the annotations and add nothing else, so what they wrap is what the
 * program actually locks on.
 */

#pragma once

#include <condition_variable>
#include <mutex>

#include "utils/thread_annotations.h"

/**
 * @class	Mutex
 * @brief	std::mutex carrying the capability annotation the analysis needs
 */
class CAPABILITY("mutex") Mutex {
 public:
  /**
   * @brief     Default constructor of Mutex
   */
  Mutex() = default;

  Mutex(const Mutex&) = delete;             // Delete copy constructor
  Mutex& operator=(const Mutex&) = delete;  // Delete copy assignment operator

  /**
   * @brief     Acquire the mutex, blocking until it is available
   */
  void Lock() ACQUIRE() { mtx_.lock(); }

  /**
   * @brief     Release the mutex
   */
  void Unlock() RELEASE() { mtx_.unlock(); }

  /**
   * @brief     Expose the wrapped mutex so a lock can be built on it
   * @return    Reference to the underlying std::mutex
   *
   * For UniqueLock's constructor, which has to hand std::unique_lock the one type it accepts. Locking
   * through it would step around the annotations and is what UniqueLock exists to prevent.
   */
  std::mutex& Native() { return mtx_; }

 private:
  std::mutex mtx_;  // Wrapped standard mutex
};

/**
 * @class   UniqueLock
 * @brief	Scoped lock owning a real std::unique_lock a condition variable can wait on
 */
class SCOPED_CAPABILITY UniqueLock {
 public:
  /**
   * @brief     Acquire a mutex for the lifetime of the lock
   * @param     m   Mutex to acquire
   */
  explicit UniqueLock(Mutex& m) ACQUIRE(m) : lk_(m.Native()) {}

  /**
   * @brief     Destructor of UniqueLock, releasing the mutex if it is still held
   */
  ~UniqueLock() RELEASE() = default;

  UniqueLock(const UniqueLock&) = delete;             // Delete copy constructor
  UniqueLock& operator=(const UniqueLock&) = delete;  // Delete copy assignment operator

  /**
   * @brief     Re-acquire the mutex after a manual release
   */
  void Lock() ACQUIRE() { lk_.lock(); }

  /**
   * @brief     Release the mutex before the lock leaves scope
   */
  void Unlock() RELEASE() { lk_.unlock(); }

  /**
   * @brief     Expose the wrapped lock so a condition variable can wait on it
   * @return    Reference to the underlying std::unique_lock
   *
   * A std::condition_variable releases and re-acquires the lock itself and will only take a real
   * std::unique_lock, which is the reason this class owns one rather than a plain scoped lock.
   */
  std::unique_lock<std::mutex>& Native() { return lk_; }

 private:
  std::unique_lock<std::mutex> lk_;  // Wrapped standard lock
};

/**
 * @class	ConditionVariable
 * @brief	std::condition_variable waiting through the annotated UniqueLock
 */
class ConditionVariable {
 public:
  /**
   * @brief     Block until the predicate holds, releasing the lock while waiting
   * @param     lk  Lock held by the caller
   * @param     p   Predicate, only ever evaluated with the lock held
   *
   * The analysis cannot see that for itself, so a predicate reading guarded state is annotated
   * REQUIRES at the call site rather than opting out of the checking.
   */
  template <typename Pred>
  void Wait(UniqueLock& lk, Pred p) {
    cv_.wait(lk.Native(), p);
  }

  /**
   * @brief     Wake one thread waiting on the condition variable
   */
  void NotifyOne() { cv_.notify_one(); }

 private:
  std::condition_variable cv_;  // Wrapped standard condition variable
};
