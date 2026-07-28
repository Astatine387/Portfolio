# 1. Introduction

GUI encrypted password file manager using AES-256-GCM and Argon2id, and Qt6.

![Windows](https://img.shields.io/badge/Windows-0078D6?logo=windows&logoColor=white) ![Linux](https://img.shields.io/badge/Linux-FCC624?logo=linux&logoColor=black)</br>
![C++](https://img.shields.io/badge/C++-20-00599C?logo=cplusplus) ![OpenSSL](https://img.shields.io/badge/OpenSSL-3.0-721412?logo=openssl&logoColor=white) ![Qt](https://img.shields.io/badge/Qt-6-41CD52?logo=qt&logoColor=white)</br>
![Build](https://github.com/Astatine387/Portfolio/actions/workflows/build-passwordmanager.yml/badge.svg)

# 2. Features

* AES-256-GCM for vault encryption and integrity check
* Argon2id for key derivation from master password
* Qt6 graphical user interface
* Two-pass decryption that never writes unverified plaintext into disk
* Random password generator with customizable length and special characters
* Automatic clipboard clear after 30 seconds of password copy
* Search and filter entries by keyword
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
	* Hybrid of Argon2i and Argon2d, balances strength of both algorithms
		* Argon2i: Data independent memory access, resistant to side channel attack
		* Argon2d: Memory hard function, resistant to brute force attack using GPU or ASIC

## 2-2. Security Considerations

* Automatic clipboard clear after 30 seconds
* Copied passwords are excluded from OS clipboard history and cloud clipboard sync
* Constant time password comparison
* GCM tag provides integrity check, and two-pass decryption procedure verifies it before writing any plaintext into disk
* Ensured memory wipe for sensitive data using RAII pattern and `SecureZeroMemory`/`explicit_bzero`
* Keys are locked in memory using `VirtualLock`/`mlock` to prevent them from being swapped to disk
* Newly and randomly generated salt and initial vector for each session, using OS-provided CSPRNG (`BCryptGenRandom`/`getrandom`)
* Password generator guarantees at least one each of uppercase, lowercase, digit, and special character
* Vault files are re-encrypted with new salt and initial vector for each save or master password change

# 3. Specifications

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

* **Entry**
	* **Maximum Site Name Length:** 256 characters
	* **Maximum Account Length:** 256 characters
	* **Maximum Password Length:** 256 characters

* **Vault**
	* **Maximum Vault File Size:** 2 GiB
	* **Maximum Master Password Length:** 256 Characters

## 3-1. Vault File Format

**Vault Format:** 
```
Magic Number (4 Bytes) | Salt (16 Bytes) | IV (12 Bytes) | Encrypted Data | Tag (16 Bytes)
```

**Encrypted Data Format:** 
```
Entry Count (4 Bytes) | Entries
```

**Entry Format:** 
```
Site Name Length (4 Bytes) | Site Name | Account Length (4 Bytes) | Account | Password Length (4 Bytes) | Password
```

**Entry Example:** 
```
{ 
	site: "Google", 
	acc: "username@google.com", 
	pw: "password" 
}
```

## 3-2. Source Code Architecture

```
src
├── Common
│   ├── constants.h            # Constant values
│   └── main.cpp               # Application entry point
├── Core
│   ├── aes_gcm.h/cpp          # AES-GCM engine
│   ├── aes_gcm_enc.cpp        # Encryption implementation
│   ├── aes_gcm_dec.cpp        # Decryption implementation
│   ├── entry.h/cpp            # Password entry struct with serialization
│   ├── vault.cpp              # Vault basic functions
│   ├── vault_file.cpp         # Vault file management (new, open, save)
│   └── vault_entry.cpp        # Vault entry CRUD operations
├── GUI
│   ├── entry_interface.h/cpp  # Interface of Entry class
│   ├── main_gui.h/cpp         # Main workflow controller
│   ├── login_gui.h/cpp        # Vault file selection
│   ├── password_gui.h/cpp     # Master password input
│   ├── list_gui.h/cpp         # Entry list with search line
│   ├── entry_gui.h/cpp        # Entry add/edit dialog with password generator
│   ├── change_pw_gui.h/cpp    # Master password change dialog
│   ├── pw_line_edit.h/cpp     # Password input component with show/hide toggle
│   └── vault_interface.h/cpp  # Interface of Vault class
└── Utils
    ├── password.h/cpp         # Secure password container
    ├── platform.h             # Utility function declarations
    ├── platform.cpp           # Common utility functions
    ├── platform_linux.cpp     # Linux utility functions
    └── platform_win32.cpp     # Windows utility functions
```

## 3-3. Limitations

* No CLI mode (GUI only)
* No key file support (Password only)
* No cloud sync (Local vault file only)
* No auto-lock on idle
* No auto-type (clipboard only)

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

Dependencies (OpenSSL 3.0+, Argon2, libsodium, Google Test) are declared in
`vcpkg.json` and installed automatically when building with the vcpkg toolchain.

## 4-2. Build

**Windows** (vcpkg manifest mode — dependencies are resolved from `vcpkg.json`):
```cmd
cd Projects\PasswordManager

cmake -B build ^
  -DCMAKE_TOOLCHAIN_FILE=%VCPKG_ROOT%\scripts\buildsystems\vcpkg.cmake ^
  -DVCPKG_TARGET_TRIPLET=x64-windows ^
  -DCMAKE_PREFIX_PATH=C:\Qt\6.7.0\msvc2019_64

cmake --build build --config Release
```
Replace `CMAKE_PREFIX_PATH` with your Qt installation path.

**Linux** (system packages):
```bash
sudo apt-get update
sudo apt-get install -y qt6-base-dev libssl-dev libargon2-dev \
                        libsodium-dev libgtest-dev

cd Projects/PasswordManager
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

**Linux** (vcpkg): libsodium must be linked dynamically, so an overlay triplet
is supplied in `triplets/`:
```bash
cd Projects/PasswordManager

cmake -B build \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_TOOLCHAIN_FILE="$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake" \
  -DVCPKG_TARGET_TRIPLET=x64-linux-dynsodium \
  -DVCPKG_OVERLAY_TRIPLETS="$PWD/triplets"

cmake --build build
```

**Build Options:** 

| Option     | Default | Description                                   |
| ---------- | ------- | --------------------------------------------- |
| `COVERAGE` | `OFF`   | Coverage instrumentation (GCC/Clang)          |
| `SANITIZE` | `OFF`   | AddressSanitizer + UndefinedBehaviorSanitizer |

Sanitizer and coverage builds require `-DCMAKE_BUILD_TYPE=Debug`:
```bash
cmake -B build -DCMAKE_BUILD_TYPE=Debug -DTHREAD_SANITIZE=ON
cmake --build build
```

## 4-3. Usage

![LoginGUI](LoginGUI.png)

![PasswordGUI](PasswordGUI.png)

![ListGUI](ListGUI.png)

![EntryGUI](EntryGUI.png)

![ChangePWGUI](ChangePWGUI.png)

1\. Run the executable `PasswordManager.exe` or `PasswordManager`
2\. Create a new vault or open an existing vault
3\. Enter master password
4\. Add, edit, or delete password entries
5\. Click Save to encrypt and store the vault

# 5. Testing
## 5-1. Coverage

![Codecov](https://codecov.io/gh/Astatine387/Portfolio/branch/main/graph/badge.svg?flag=passwordmanager)

| File                     | Tracked Lines | Covered | Partial | Missed | Coverage % |
| ------------------------ | ------------- | ------- | ------- | ------ | ---------- |
| core/aes_gcm.cpp         | 23            | 23      | 0       | 0      | 100.00%    |
| core/aes_gcm.h           | 1             | 1       | 0       | 0      | 100.00%    |
| core/aes_gcm_dec.cpp     | 53            | 53      | 0       | 0      | 100.00%    |
| core/aes_gcm_enc.cpp     | 46            | 46      | 0       | 0      | 100.00%    |
| core/entry.cpp           | 48            | 48      | 0       | 0      | 100.00%    |
| core/entry.h             | 4             | 4       | 0       | 0      | 100.00%    |
| core/vault.cpp           | 27            | 27      | 0       | 0      | 100.00%    |
| core/vault.h             | 1             | 1       | 0       | 0      | 100.00%    |
| core/vault_entry.cpp     | 29            | 29      | 0       | 0      | 100.00%    |
| core/vault_file.cpp      | 104           | 102     | 0       | 2      | 98.08%     |
| utils/password.cpp       | 35            | 35      | 0       | 0      | 100.00%    |
| utils/password.h         | 25            | 25      | 0       | 0      | 100.00%    |
| utils/platform.cpp       | 23            | 23      | 0       | 0      | 100.00%    |
| utils/platform_linux.cpp | 39            | 35      | 0       | 8      | 89.74%     |

| Module   | Test File              | Test Cases                                                                                                                       |
| -------- | ---------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| AesGcm   | `aes_gcm_test.cpp`     | Encryption, Decryption, Authentication, Integrity Check, Edge Cases, Error Callback                                              |
| Entry    | `entry_test.cpp`       | Size Calculation, Comparison, Serialization, Deserialization, Boundary Check, Field Length Validation                            |
| Password | `password_test.cpp`    | Initialization, Setting Data, Copy and Move Semantics, Memory Safety, RAII, Comparison, Data, Cleanup, Maximum Size, Memory Lock |
| Utils    | `utils_test.cpp`       | File Handling, Argon2id Key Derivation, Random Number Generation, Memory Wipe                                                    |
| Vault    | `vault_entry_test.cpp` | Entry CRUD Operation, Duplication Check, Existence Check, Conflict Check, Accessor, Master Password Verification                 |
| Vault    | `vault_file_test.cpp`  | Vault Creation, Opening, Validation, Save, Password Change, Error Handling                                                       |

**Note:** GUI files, error messages for external libraries and system calls are excluded from tests.

## 5-2. Running Tests

**Windows:**
```cmd
cd Projects/PasswordManager
ctest --test-dir build -C Release --output-on-failure
```

**Linux:**
```bash
cd Projects/PasswordManager
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

# 6. License

* This project is licensed under the MIT License. See [LICENSE.md](LICENSE.md) for more details.
* This project uses the following third-party libraries. See [LICENSES-THIRD-PARTY.md](LICENSES-THIRD-PARTY.md) for more details.
	- OpenSSL (Apache 2.0)
	- Argon2 (CC0/Apache 2.0)
	- Qt (LGPL v3)
	- Google Test (BSD 3-Clause)
