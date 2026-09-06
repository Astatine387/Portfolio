# 1. Introduction

Password-based GUI file encryption/decryption tool using AES-256-GCM and Argon2id, and Qt6.

![Windows](https://img.shields.io/badge/Windows-0078D6?logo=windows&logoColor=white) ![Linux](https://img.shields.io/badge/Linux-FCC624?logo=linux&logoColor=black)</br>
![C++](https://img.shields.io/badge/C++-20-00599C?logo=cplusplus) ![OpenSSL](https://img.shields.io/badge/OpenSSL-3.0-721412?logo=openssl&logoColor=white) ![Qt](https://img.shields.io/badge/Qt-6-41CD52?logo=qt&logoColor=white)</br>
![Build](https://github.com/Astatine387/Portfolio/actions/workflows/build-fileencryption.yml/badge.svg)

# 2. Features

* AES-256-GCM for file encryption and integrity check
* Argon2id for key derivation from password
* Qt6 graphical user interface
* Chunked AEAD file format, each chunk authenticated on its own
* Decryption authenticates every byte before it reaches the disk
* Atomic write: the destination path never holds an incomplete file
* Double buffering and asynchronous write for better performance 
* Asynchronous, multithread processing for non-blocking UI
* Real-time progress tracking and cancellation support
* Error report and automatic stop on failure
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

* Every byte written to disk has been authenticated first, and the source is read exactly once
* The plaintext header is authenticated as associated data of every chunk, so editing it is detected
* Chunk order, truncation and extension are detected, because the nonce carries the chunk counter and a final-chunk flag
* Newly and randomly generated salt for each session, using OS-provided CSPRNG (`BCryptGenRandom`/`getrandom`)
* RAII pattern ensures memory wipe for sensitive data, using `sodium_free` and `sodium_memzero`
* Range check for the chunk size and the key derivation parameters before anything is allocated or Argon2id runs
* Sensitive data is held in `sodium_malloc` memory, which provides guard pages and lock against swap
* Output is written to a temporary file, fsynced, then moved into place, so a partial or unverified file never appears at the destination
* The destination is never overwritten: the move fails if the path is taken

# 3. Specifications

* **AES-256-GCM**
	* **Nonce Size:** 96 bits (recommended for AES-256-GCM)
	* **Key Size:** 256 bits (using AES-256)
	* **Block Size:** 128 bits (using AES)
	* **Authentication Tag Size:** 128 bits (one per chunk)

* **Argon2id**
	* **Memory Cost:** 512 MiB
	* **Time Cost:** 4 iterations
	* **Parallelism:** 4
	* **Salt Size:** 128 bits

* **Chunk Size:** 64 KiB default, 4 KiB to 1 MiB accepted

* **Maximum File Size:** 2 ^ 64 chunks

## 3-1. Encrypted File Format

A file is a plaintext header followed by a sequence of independently authenticated chunks. The construction is STREAM (Hoang-Reyhanitabar-Rogaway-Vizar, 2015), the same framing `age` and Google Tink use.

```
Header (33 Bytes) │ Chunk 0 │ Chunk 1 │ ... │ Chunk N-1
```

### 3-1-1. Header

33 bytes, plaintext, and fed to every chunk as associated data.

| Offset | Size | Field         | Encoding                                 |
|-------:|-----:|---------------|------------------------------------------|
| 0      | 4    | Magic         | `E0 7B CA 75`                            |
| 4      | 1    | ChunkSizeLog2 | uint8, accepted range 12..20, default 16 |
| 5      | 4    | TimeCost      | uint32 little-endian                     |
| 9      | 4    | MemCost       | uint32 little-endian (KiB)               |
| 13     | 4    | Parallelism   | uint32 little-endian                     |
| 17     | 16   | Salt          | raw bytes                                |

### 3-1-2. Chunk

```
Chunk_i = Ciphertext_i (L_i bytes) ‖ Tag_i (16 Bytes)
```

* `C = 1 << ChunkSizeLog2` is the chunk size in bytes
* `L_i = C` for every chunk except the last
* `0 <= L_last <= C`; the last chunk may be exactly `C` bytes
* A file always contains at least one chunk, so a 0-byte plaintext produces one chunk with `L = 0`
* Total file size is not stored; Chunk boundaries are derived from the file size

### 3-1-3. Nonce

12 bytes, not stored in the file, instead derived from the chunk counter and file size

```
nonce[0..10] = chunk counter, big-endian, starts at 0, +1 per chunk
nonce[11]    = 0x00 for a normal chunk, 0x01 for the final chunk
```

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
    ├── byte_order.h          # Explicit little/big-endian helpers for on-disk fields
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
vcpkg toolchain.

Google Benchmark is Linux-only and optional: `FileEncryption-bench` is never generated on Windows, and on Linux it is skipped when Benchmark is absent.

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

| Module        | Test File                 | Test Cases                                                                                                          |
| ------------- | ------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| Known Answer  | `kat_test.cpp`            | NIST CAVP AES-256-GCM vectors, RFC 9106 Argon2id vector, Tag Rejection                                              |
| AesGcm        | `aes_gcm_test.cpp`        | Encryption, Decryption, Header, Authentication, Edge Cases, Callbacks, Cancellation, Write Failures                 |
| AesGcm Format | `aes_gcm_format_test.cpp` | Chunk Framing, Golden Vector with byte-exact header, Associated Data, Context Reuse                                 |
| AesGcm Tamper | `aes_gcm_tamper_test.cpp` | Header and Chunk Bit Flips, Reordering, Truncation, Appending, Splicing, Write Ordering                             |
| CryptoWorker  | `crypto_worker_test.cpp`  | Encryption, Decryption, Header Parameters, Atomic Publication, Callbacks, Cancellation, Error Handling, Concurrency |
| FileHeader    | `file_header_test.cpp`    | Field Layout and Endianness, Magic Number, Chunk Size and Parameter Validation, Error Messages                      |
| Byte Order    | `byte_order_test.cpp`     | Little-Endian and Big-Endian Encoding, Round Trips, Field Bounds                                                    |
| OpenNewFile   | `open_new_file_test.cpp`  | Exclusive Creation, Permissions, Symlink and FIFO Refusal, Close-on-Exec                                            |
| Password      | `password_test.cpp`       | Initialization, Setting Data, Copy and Move Semantics, Memory Safety, RAII                                          |
| SecureKey     | `secure_key_test.cpp`     | Argon2id Key Derivation, Salt and Password Sensitivity, Parameter Rejection, Move Semantics                         |
| Utils         | `utils_test.cpp`          | File Handling, Durability Helpers, Random Number Generation                                                         |

The known-answer tests are the correctness anchor: their values come from the NIST CAVP response files and the RFC 9106 text, never from this implementation. The golden vector in `aes_gcm_format_test.cpp` is the opposite kind of test, a regression pin generated by this code to catch accidental format drift.

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

**Source:** https://github.com/Astatine387/Portfolio/actions/runs/33981343212

| Metric                                              |     Value |
| --------------------------------------------------- | --------: |
| Encryption pipeline / raw OpenSSL EVP               | **35.0%** |
| Decryption pipeline / raw OpenSSL EVP               | **34.0%** |
| Argon2id key derivation (m = 512 MiB, t = 4, p = 4) |    791429 |

# 7. License

* This project is licensed under the MIT License. See [LICENSE.md](LICENSE.md) for more details.
* This project uses the following third-party libraries. See [LICENSES-THIRD-PARTY.md](LICENSES-THIRD-PARTY.md) for more details.
	- OpenSSL (Apache 2.0)
	- Argon2 (CC0/Apache 2.0)
	- Qt (LGPL v3)
	- Google Test (BSD 3-Clause)
