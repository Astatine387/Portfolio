cmake_minimum_required(VERSION 3.16)
project(PasswordManager VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

# Coverage
option(COVERAGE "Enable coverage reporting" OFF)

if(COVERAGE AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    message(STATUS "Coverage enabled")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} --coverage -fprofile-arcs -ftest-coverage")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} --coverage")
endif()

# Qt6
find_package(Qt6 REQUIRED COMPONENTS Core Gui Widgets)

# OpenSSL
find_package(OpenSSL 3.0 REQUIRED)

# GoogleTest
find_package(GTest CONFIG REQUIRED)

# Argon2
find_library(ARGON2_LIBRARY NAMES argon2)
find_path(ARGON2_INCLUDE_DIR argon2.h)

if(NOT ARGON2_LIBRARY OR NOT ARGON2_INCLUDE_DIR)
    message(FATAL_ERROR "Argon2 library not found")
endif()

set(LIB_SOURCES
    src/Core/AES_GCM.cpp
    src/Core/AES_GCM_dec.cpp
    src/Core/AES_GCM_enc.cpp
    src/Core/Entry.cpp
    src/Core/Vault.cpp
    src/Core/Vault_file.cpp
    src/Core/Vault_entry.cpp
    src/GUI/ChangePWGUI.cpp
    src/GUI/EntryGUI.cpp
    src/GUI/ListGUI.cpp
    src/GUI/LoginGUI.cpp
    src/GUI/MainGUI.cpp
    src/GUI/PasswordGUI.cpp
    src/GUI/PWLineEdit.cpp
    src/Utils/library.cpp
    src/Utils/Password.cpp
)

set(HEADERS
    src/Common/constants.h
    src/Core/AES_GCM.h
    src/Core/Entry.h
    src/Core/Vault.h
    src/GUI/ChangePWGUI.h
    src/GUI/EntryGUI.h
    src/GUI/ListGUI.h
    src/GUI/LoginGUI.h
    src/GUI/MainGUI.h
    src/GUI/PasswordGUI.h
    src/GUI/PWLineEdit.h
    src/Utils/library.h
    src/Utils/Password.h
)

add_library(PasswordManager-lib STATIC ${LIB_SOURCES} ${HEADERS})

target_include_directories(PasswordManager-lib PUBLIC
    ${CMAKE_SOURCE_DIR}/src
    ${ARGON2_INCLUDE_DIR}
)

target_link_libraries(PasswordManager-lib PUBLIC
    Qt6::Core
    Qt6::Gui
    Qt6::Widgets
    OpenSSL::Crypto
    ${ARGON2_LIBRARY}
)

if(WIN32)
    target_link_libraries(PasswordManager-lib PUBLIC bcrypt)
endif()

add_executable(${PROJECT_NAME} src/Common/main.cpp)
target_link_libraries(${PROJECT_NAME} PRIVATE PasswordManager-lib)

enable_testing()

set(TEST_SOURCES
    src/Tests/AES_GCM_Test.cpp
    src/Tests/EntryTest.cpp
    src/Tests/PasswordTest.cpp
    src/Tests/UtilsTest.cpp
    src/Tests/VaultEntryTest.cpp
    src/Tests/VaultFileTest.cpp
)

add_executable(PasswordManager-tests ${TEST_SOURCES})

target_link_libraries(PasswordManager-tests PRIVATE
    PasswordManager-lib
    GTest::gtest
    GTest::gtest_main
)

include(GoogleTest)
gtest_discover_tests(PasswordManager-tests)