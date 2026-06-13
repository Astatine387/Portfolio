# 1. Introduction

Password-based GUI file encryption/decryption tool using AES-256-GCM and Argon2id, and Qt6.

![Windows](https://img.shields.io/badge/Windows-0078D6?logo=windows&logoColor=white) ![Linux](https://img.shields.io/badge/Linux-FCC624?logo=linux&logoColor=black)</br>
![C++](https://img.shields.io/badge/C++-20-00599C?logo=cplusplus) ![OpenSSL](https://img.shields.io/badge/OpenSSL-3.0-721412?logo=openssl&logoColor=white) ![Qt](https://img.shields.io/badge/Qt-6-41CD52?logo=qt&logoColor=white)</br>
![Build](https://github.com/Astatine387/Portfolio/actions/workflows/build-fileencryption.yml/badge.svg)

# 2. Features

* 2 GiB/s Google Benchmark encryption throughput
* AES-256-GCM for file encryption and integrity check
* Argon2id for key derivation from password
* Qt6 graphical user interface
* Double buffering and asynchronous write for better performance 
* Two-pass decryption that never writes unverified plaintext into disk
* Asynchronous, multithread processing for non-blocking UI
* Real-time progress tracking and cancellation support
* Error report and automatic stop when error occurs
* Cross-platform support for Windows and Linux

## 2-1. Why use this?

* **AES-GCM**
	* **AES**
		* Most used encryption algorithm, de facto industry standard
		* Chosen by NIST, trusted by many governments and corporations
		* Modern processors support hardware acceleration for AES
	* **GCM**
		* Does not require padding, immune to padding oracle attack
		* Can be parallelized in both encryption and decryption process 
		* Provides both confidentiality and integrity using AEAD

* **Argon2id**
	* Winner of 2015 Password Hashing Competition
	* Recommendation of OWASP and RFC 9106
	* Hybrid of Argon2i and Argon2d, balances strength of both algorithms
		* Argon2i: Data independent memory access, resistant to side channel attack
		* Argon2d: Memory hard function, resistant to brute force attack using GPU or ASIC

## 2-2. Security Considerations

* GCM tag provides integrity check, and two-pass decryption procedure verifies it before writing any plaintext into disk
* Ensured memory wipe for sensitive data using RAII pattern and `SecureZeroMemory`/`explicit_bzero`
* Keys are locked in memory using `VirtualLock`/`mlock` to prevent them from being swapped to disk
* Newly and randomly generated salt and initial vector for each session, using OS-provided CSPRNG (`BCryptGenRandom`/`getrandom`)

# 3. Specifications

* **Maximum File Size:** 68,719,476,704 bytes (Maximum of AES-GCM)

* **AES-256-GCM**
	* **IV Size:** 96 bits (recommended for AES-256-GCM)
	* **Key Size:** 256 bits (using AES-256)
	* **Block Size:** 128 bits (using AES)
	* **Authentication Tag Size:** 128 bits

* **Argon2id**
	* **Memory Cost:** 512 MiB
	* **Time Cost:** 4 iterations
	* **Parallelism:** 4
	* **Salt Size:** 128 bits

* **Buffer Size:** 4096 blocks (64 KiB)

## 3-1. Encrypted File Format

```
Salt (16 Bytes) │ IV (12 Bytes) │ Encrypted Data │ Tag (16 Bytes)
```

## 3-2. Source Code Architecture

```
src
├── Common
│   ├── constants.h           # Constant values
│   └── main.cpp              # Application entry point
├── Core
│   ├── aes_gcm.h/cpp         # AES-GCM engine
│   ├── aes_gcm_enc.cpp       # Encryption implementation
│   ├── aes_gcm_dec.cpp       # Decryption implementation
│   └── crypto_worker.h/cpp   # Asynchronous worker thread
├── GUI
│   ├── crypto_wrapper.h/cpp  # Wrapper class for CryptoWorker
│   ├── main_gui.h/cpp        # Main workflow controller
│   ├── input_gui.h/cpp       # Source, destination, and password input
│   ├── progress_gui.h/cpp    # Progress tracking
│   ├── mode_button.h/cpp     # Encrypt/Decrypt mode selection widget
│   └── pw_line_edit.h/cpp    # Password input widget
└── Utils
    ├── password.h/cpp        # Secure password container
    ├── platform.h            # Utility function declarations
    ├── platform.cpp          # Common utility functions
    ├── platform_linux.cpp    # Linux utility functions
    └── platform_win32.cpp    # Windows utility functions
```

## 3-3. Limitations

* No batch encryption (Single file only)
* No CLI mode (GUI only)
* No key file support (Password only)
* No log file (GUI message and progress bar only)
* No original file removal

# 4. Build and Usage
## 4-1. Prerequisites

**Windows:**
* Visual Studio 2022+ with C++ workload
* CMake 3.16+
* vcpkg
* Qt 6.7+

**Linux:**
* GCC 11+ or Clang 14+
* CMake 3.16+
* Qt6 development packages

## 4-2. Build

**Windows:**
```cmd
# Install dependencies
vcpkg install openssl:x64-windows argon2:x64-windows gtest:x64-windows

# Configure and build
cd Projects/FileEncryption
cmake -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_TOOLCHAIN_FILE=%VCPKG_ROOT%/scripts/buildsystems/vcpkg.cmake
cmake --build build --config Release
```

**Linux:**
```bash
# Install dependencies
sudo apt-get install qt6-base-dev libssl-dev libargon2-dev libgtest-dev

# Configure and build
cd Projects/FileEncryption
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

## 4-3. Usage

![InputGUI](InputGUI.png)

![ProgressGUI](ProgressGUI.png)

1. Run the executable `FileEncryption.exe` or `FileEncryption`
2. Select mode
3. Enter source file path
4. Enter destination file path
5. Enter password
6. Click Start

# 5. Testing
## 5-1. Coverage

![Codecov](https://codecov.io/gh/Astatine387/Portfolio/branch/main/graph/badge.svg?flag=fileencryption)

| File                     | Tracked Lines | Covered | Partial | Missed | Coverage % |
| ------------------------ | ------------- | ------- | ------- | ------ | ---------- |
| core/aes_gcm.cpp         | 75            | 74      | 0       | 1      | 98.67%     |
| core/aes_gcm.h           | 2             | 2       | 0       | 0      | 100.00%    |
| core/aes_gcm_dec.cpp     | 67            | 67      | 0       | 0      | 100.00%    |
| core/aes_gcm_enc.cpp     | 68            | 68      | 0       | 0      | 100.00%    |
| core/crypto_worker.cpp   | 51            | 51      | 0       | 0      | 100.00%    |
| core/crypto_worker.h     | 4             | 4       | 0       | 0      | 100.00%    |
| utils/password.cpp       | 26            | 26      | 0       | 0      | 100.00%    |
| utils/password.h         | 25            | 25      | 0       | 0      | 100.00%    |
| utils/platform.cpp       | 3             | 3       | 0       | 0      | 100.00%    |
| utils/platform_linux.cpp | 33            | 30      | 0       | 6      | 90.91%     |

| Module       | Test File                | Test Cases                                                                                   |
| ------------ | ------------------------ | -------------------------------------------------------------------------------------------- |
| AesGcm       | `aes_gcm_test.cpp`       | Encryption, Decryption, Authentication, Integrity Check, Edge Cases, Callbacks, Cancellation |
| CryptoWorker | `crypto_worker_test.cpp` | Encryption, Decryption, Callbacks, Cancellation, Error Handling, Concurrency                 |
| Password     | `password_test.cpp`      | Initialization, Setting Data, Copy and Move Semantics, Memory Safety, RAII                   |
| Utils        | `utils_test.cpp`         | File Handling, Argon2id Key Derivation, Random Number Generation, Memory Wipe                |

**Note:** GUI files, error messages for external libraries and system calls are excluded from tests.

## 5-2. Running Tests

**Windows:**
```cmd
cd Projects/FileEncryption
ctest --test-dir build -C Release --output-on-failure
```

**Linux:**
```bash
cd Projects/FileEncryption
ctest --test-dir build --output-on-failure
```

## 5-3. Continuous Integration

| Check | Windows | Linux |
|-------|---------|-------|
| Build | ✅ MSVC 2022 | ✅ GCC 11+ |
| Unit Tests | ✅ | ✅ |
| Static Analysis (cppcheck) | - | ✅ |
| Coverage Report | - | ✅ Codecov |

# 6. Benchmark

* **Test Environment** (Local)
	* **OS:** Windows 11 Pro
	* **CPU:** Intel Core i9-13980HX (24 Cores / 32 Threads)
	* **RAM:** 16 GB DDR5-4800
	* **Storage:** Micron 2400 NVMe SSD (1TB)
	* **File Size:** 4 GiB

* **Results** (on cold start)
	* **Encryption:** 1.1 ~ 1.3 GiB/s
	* **Decryption:** 1.2 ~ 1.3 GiB/s
	* **Argon2id Key Derivation:** 430ms

* **Results** (after warm-up)
	* **Encryption:** 1.9 ~ 2.1 GiB/s
	* **Decryption:** 2.0 ~ 2.1 GiB/s
	* **Argon2id Key Derivation:** 310ms

**Running Benchmarks Locally:** 
```cmd
cd Projects/FileEncryption
cmake -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_TOOLCHAIN_FILE="%VCPKG_ROOT%/scripts/buildsystems/vcpkg.cmake" -DCMAKE_PREFIX_PATH="C:/Qt/6.10.1/msvc2022_64" -DVCPKG_TARGET_TRIPLET=x64-windows
cmake --build build --config Release --target FileEncryption-bench
.\build\Release\FileEncryption-bench.exe
```

# 7. License

* This project is licensed under the MIT License. See [LICENSE.md](LICENSE.md) for more details.
* This project uses the following third-party libraries. See [LICENSES-THIRD-PARTY.md](LICENSES-THIRD-PARTY.md) for more details.
	- OpenSSL (Apache 2.0)
	- Argon2 (CC0/Apache 2.0)
	- Qt (LGPL v3)
	- Google Test (BSD 3-Clause)
