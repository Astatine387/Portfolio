/**
 * @file	thread_annotations.h
 * @brief	Portable wrappers around Clang's thread safety analysis attributes
 * @author	Astatine387
 */

#pragma once

#if defined(__clang__)
#define THREAD_ANNOTATION_ATTRIBUTE(x) __attribute__((x))
#else
#define THREAD_ANNOTATION_ATTRIBUTE(x)
#endif

/**
 * @brief	Mark a class as a capability the analysis can track
 * @param	x	Name used for the capability in diagnostics
 */
#define CAPABILITY(x) THREAD_ANNOTATION_ATTRIBUTE(capability(x))

/**
 * @brief	Mark a class as an RAII object holding a capability for its lifetime
 */
#define SCOPED_CAPABILITY THREAD_ANNOTATION_ATTRIBUTE(scoped_lockable)

/**
 * @brief	Declare that a member may only be accessed while a capability is held
 * @param	x	Capability guarding the member
 */
#define GUARDED_BY(x) THREAD_ANNOTATION_ATTRIBUTE(guarded_by(x))

/**
 * @brief	Declare that the data behind a pointer member is guarded by a capability
 * @param	x	Capability guarding the pointed-to data
 */
#define PT_GUARDED_BY(x) THREAD_ANNOTATION_ATTRIBUTE(pt_guarded_by(x))

/**
 * @brief	Declare that a function may only be called while capabilities are held
 * @param	...		Capabilities that must be held on entry
 */
#define REQUIRES(...) THREAD_ANNOTATION_ATTRIBUTE(requires_capability(__VA_ARGS__))

/**
 * @brief	Declare that a function acquires capabilities without releasing them
 * @param	...		Capabilities acquired on return
 */
#define ACQUIRE(...) THREAD_ANNOTATION_ATTRIBUTE(acquire_capability(__VA_ARGS__))

/**
 * @brief	Declare that a function releases capabilities held on entry
 * @param	...		Capabilities released on return
 */
#define RELEASE(...) THREAD_ANNOTATION_ATTRIBUTE(release_capability(__VA_ARGS__))

/**
 * @brief	Declare that a function must not be called while capabilities are held
 * @param	...		Capabilities that must not be held on entry
 */
#define EXCLUDES(...) THREAD_ANNOTATION_ATTRIBUTE(locks_excluded(__VA_ARGS__))

/**
 * @brief	Turn off thread safety analysis for a single function
 */
#define NO_THREAD_SAFETY_ANALYSIS THREAD_ANNOTATION_ATTRIBUTE(no_thread_safety_analysis)
