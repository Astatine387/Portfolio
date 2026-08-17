# 1. Introduction

Password-based GUI file encryption/decryption tool using AES-256-GCM and Argon2id, and Qt6.

![Windows](https://img.shields.io/badge/Windows-0078D6?logo=windows&logoColor=white) ![Linux](https://img.shields.io/badge/Linux-FCC624?logo=linux&logoColor=black)</br>
![C++](https://img.shields.io/badge/C++-20-00599C?logo=cplusplus) ![OpenSSL](https://img.shields.io/badge/OpenSSL-3.0-721412?logo=openssl&logoColor=white) ![Qt](https://img.shields.io/badge/Qt-6-41CD52?logo=qt&logoColor=white)</br>
![Build](https://github.com/Astatine387/Portfolio/actions/workflows/build-fileencryption.yml/badge.svg)

# 2. Features

* Up to 2+ GiB/s Google Benchmark throughput in encryption
* AES-256-GCM for file encryption and integrity check
* Argon2id for key derivation from password
* Qt6 graphical user interface
* Double buffering and asynchronous write for better performance 
* Two-pass decryption that never writes unverified plaintext into disk
* Asynchronous, multithread processing for non-blocking UI
* Real-time progress tracking and cancellation support
* Error report and automatic stop when error occurs
* Cross-platform support for Windows and Linux

## 2-1. Cryptographic Choice

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
* Newly and randomly generated salt and initial vector for each session, using OS-provided CSPRNG (`BCryptGenRandom`/`getrandom`)
* RAII pattern ensures memory wipe for sensitive data, using `sodium_free` and `sodium_memzero`
* Range check for key derivation parameters before Argon2id runs
* Sensitive data is held in `sodium_malloc` memory, which provides guard pages and lock against swap

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
Magic Number (4 Bytes) │ Time Cost (4 Bytes) │ Memory Cost (4 Bytes) │ Parallelism (4 Bytes) │ Salt (16 Bytes) │ IV (12 Bytes) │ Encrypted Data │ Tag (16 Bytes)
```

* Multi-byte integers are stored little-endian, and the memory cost is stored in KiB.

## 3-2. Source Code Architecture

```
src
├── common
│   ├── constants.h           # Constant values
│   └── main.cpp              # Application entry point
├── core
│   ├── aes_gcm.h/cpp         # AES-GCM engine
│   ├── aes_gcm_enc.cpp       # Encryption
│   ├── aes_gcm_dec.cpp       # Decryption
│   ├── crypto_worker.h/cpp   # Asynchronous worker thread
│   ├── file_header.h/cpp     # Encrypted file header
│   └── secure_key.h/cpp      # Secure AES key handler
├── gui
│   ├── crypto_wrapper.h/cpp  # Wrapper class for CryptoWorker
│   ├── main_gui.h/cpp        # Main workflow controller
│   ├── input_gui.h/cpp       # Source, destination, and password input
│   ├── progress_gui.h/cpp    # Progress tracking
│   ├── mode_button.h/cpp     # Encrypt/Decrypt mode selection widget
│   └── pw_line_edit.h/cpp    # Password input widget
└── utils
    ├── password.h/cpp        # Secure password container
    ├── platform.h            # Utility function declarations
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
* Visual Studio 2022+ with the "Desktop development with C++" workload
* CMake 3.16+
* vcpkg
* Qt 6.7+

**Linux:**
* GCC 11+ or Clang 14+
* CMake 3.16+
* Qt6 development packages

Dependencies (OpenSSL 3.0+, Argon2, libsodium, Google Test, Google Benchmark)
are declared in `vcpkg.json` and installed automatically when building with the
vcpkg toolchain. Google Benchmark is optional: without it the `FileEncryption-bench`
target is simply not generated.

## 4-2. Build

**Windows** (vcpkg manifest mode — dependencies are resolved from `vcpkg.json`):
```cmd
cd Projects\FileEncryption

cmake -B build ^
  -DCMAKE_TOOLCHAIN_FILE=%VCPKG_ROOT%\scripts\buildsystems\vcpkg.cmake ^
  -DVCPKG_TARGET_TRIPLET=x64-windows ^
  -DCMAKE_PREFIX_PATH=C:\Qt\6.7.0\msvc2019_64

cmake --build build --config Release
```
* Replace `CMAKE_PREFIX_PATH` with your Qt installation path.

**Linux** (system packages):
```bash
sudo apt-get update
sudo apt-get install -y qt6-base-dev libssl-dev libargon2-dev \
                        libsodium-dev libgtest-dev libbenchmark-dev

cd Projects/FileEncryption
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

**Linux** (vcpkg): libsodium must be linked dynamically, so an overlay triplet
is supplied in `triplets/`:
```bash
cd Projects/FileEncryption

cmake -B build \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_TOOLCHAIN_FILE="$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake" \
  -DVCPKG_TARGET_TRIPLET=x64-linux-dynsodium \
  -DVCPKG_OVERLAY_TRIPLETS="$PWD/triplets"

cmake --build build
```

**Build Options:** 

| Option            | Default | Description                                   |
| ----------------- | ------- | --------------------------------------------- |
| `COVERAGE`        | `OFF`   | Coverage instrumentation (GCC/Clang)          |
| `SANITIZE`        | `OFF`   | AddressSanitizer + UndefinedBehaviorSanitizer |
| `THREAD_SANITIZE` | `OFF`   | ThreadSanitizer                               |

Sanitizer and coverage builds require `-DCMAKE_BUILD_TYPE=Debug`:
```bash
cmake -B build -DCMAKE_BUILD_TYPE=Debug -DTHREAD_SANITIZE=ON
cmake --build build
```

## 4-3. Usage

![InputGUI](InputGUI.png)

![ProgressGUI](ProgressGUI.png)

1\. Run the executable `FileEncryption.exe` or `FileEncryption`
2\. Select mode
3\. Enter source file path
4\. Enter destination file path
5\. Enter password
6\. Click Start

# 5. Testing
## 5-1. Coverage

![Codecov](https://codecov.io/gh/Astatine387/Portfolio/branch/main/graph/badge.svg?flag=fileencryption)

**Codecov Report:** https://app.codecov.io/gh/Astatine387/Portfolio/tree/main/Projects%2FFileEncryption%2Fsrc

| Module       | Test File                | Test Cases                                                                                          |
| ------------ | ------------------------ | --------------------------------------------------------------------------------------------------- |
| AesGcm       | `aes_gcm_test.cpp`       | Encryption, Decryption, Header, Authentication, Integrity Check, Edge Cases, Callbacks, Cancellation |
| CryptoWorker | `crypto_worker_test.cpp` | Encryption, Decryption, Header Parameters, Callbacks, Cancellation, Error Handling, Concurrency      |
| FileHeader   | `file_header_test.cpp`   | Header Layout, Magic Number, Parameter Validation, Error Messages                                    |
| Password     | `password_test.cpp`      | Initialization, Setting Data, Copy and Move Semantics, Memory Safety, RAII                          |
| Utils        | `utils_test.cpp`         | File Handling, Argon2id Key Derivation, Random Number Generation, Memory Wipe                       |

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

| Check                        | Windows     | Linux     |
| ---------------------------- | ----------- | --------- |
| Build                        | ✅ MSVC 2022 | ✅ GCC 11+ |
| Unit Tests                   | ✅           | ✅         |
| Format Check (clang-format)  | -           | ✅         |
| Static Analysis (cppcheck)   | -           | ✅         |
| Static Analysis (clang-tidy) | -           | ✅         |
| Coverage Report              | -           | ✅ Codecov |
| AddressSanitizer (ASan)      | -           | ✅         |
| ThreadSanitizer (TSan)       | -           | ✅         |

# 6. Benchmark

* **Test Environment** (Local)
	* **OS:** Windows 11 Pro
	* **CPU:** Intel Core i9-13980HX (24 Cores / 32 Threads)
	* **RAM:** 16 GB DDR5-4800
	* **Storage:** Micron 2400 NVMe SSD (1TB)
	* **File Size:** 4 GiB

* **Results** (on cold start)
	* **Encryption:** 1.5 ~ 1.6 GiB/s
	* **Decryption:** 0.9 ~ 1.0 GiB/s
	* **Argon2id Key Derivation:** 380 ~ 400 ms

* **Results** (after warm-up)
	* **Encryption:** 1.9 ~ 2.1 GiB/s
	* **Decryption:** 1.3 ~ 1.4 GiB/s
	* **Argon2id Key Derivation:** 380 ~ 400 ms

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
