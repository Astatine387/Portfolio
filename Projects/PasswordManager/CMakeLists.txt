cmake_minimum_required(VERSION 3.16)
project(PasswordManager VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

option(COVERAGE "Enable coverage reporting" OFF)

if(COVERAGE AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    message(STATUS "Coverage enabled")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} --coverage -fprofile-arcs -ftest-coverage")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} --coverage")
endif()

find_package(Qt6 REQUIRED COMPONENTS Core Gui Widgets)

find_package(OpenSSL 3.0 REQUIRED)

find_package(GTest CONFIG REQUIRED)

find_library(ARGON2_LIBRARY NAMES argon2)
find_path(ARGON2_INCLUDE_DIR argon2.h)

if(NOT ARGON2_LIBRARY OR NOT ARGON2_INCLUDE_DIR)
    message(FATAL_ERROR "Argon2 library not found")
endif()

set(CORE_SOURCES
    src/Core/aes_gcm.cpp
    src/Core/aes_gcm_dec.cpp
    src/Core/aes_gcm_enc.cpp
    src/Core/entry.cpp
    src/Core/vault.cpp
    src/Core/vault_file.cpp
    src/Core/vault_entry.cpp
    src/Utils/password.cpp
    src/Utils/platform.cpp
)

if(WIN32)
    list(APPEND CORE_SOURCES src/Utils/platform_win32.cpp)
else()
    list(APPEND CORE_SOURCES src/Utils/platform_linux.cpp)
endif()

set(CORE_HEADERS
    src/Common/constants.h
    src/Core/aes_gcm.h
    src/Core/entry.h
    src/Core/vault.h
    src/Utils/password.h
    src/Utils/platform.h
)

add_library(PasswordManager-core STATIC ${CORE_SOURCES} ${CORE_HEADERS})

target_include_directories(PasswordManager-core PUBLIC
    ${CMAKE_SOURCE_DIR}/src
    ${ARGON2_INCLUDE_DIR}
)

target_link_libraries(PasswordManager-core PUBLIC
    OpenSSL::Crypto
    ${ARGON2_LIBRARY}
)

if(WIN32)
    target_link_libraries(PasswordManager-core PUBLIC bcrypt)
endif()

set(GUI_SOURCES
    src/GUI/change_pw_gui.cpp
    src/GUI/entry_gui.cpp
    src/GUI/list_gui.cpp
    src/GUI/login_gui.cpp
    src/GUI/main_gui.cpp
    src/GUI/password_gui.cpp
    src/GUI/pw_line_edit.cpp
    src/GUI/vault_interface.cpp
)

set(GUI_HEADERS
    src/GUI/change_pw_gui.h
    src/GUI/entry_gui.h
    src/GUI/entry_interface.h
    src/GUI/list_gui.h
    src/GUI/login_gui.h
    src/GUI/main_gui.h
    src/GUI/password_gui.h
    src/GUI/pw_line_edit.h
    src/GUI/vault_interface.h
)

add_library(PasswordManager-gui STATIC ${GUI_SOURCES} ${GUI_HEADERS})

target_link_libraries(PasswordManager-gui PUBLIC
    PasswordManager-core
    Qt6::Core
    Qt6::Gui
    Qt6::Widgets
)

add_executable(${PROJECT_NAME} src/Common/main.cpp)
target_link_libraries(${PROJECT_NAME} PRIVATE PasswordManager-gui)

enable_testing()

set(TEST_SOURCES
    src/Tests/aes_gcm_test.cpp
    src/Tests/entry_test.cpp
    src/Tests/password_test.cpp
    src/Tests/utils_test.cpp
    src/Tests/vault_entry_test.cpp
    src/Tests/vault_file_test.cpp
)

add_executable(PasswordManager-tests ${TEST_SOURCES})

target_link_libraries(PasswordManager-tests PRIVATE
    PasswordManager-core
    GTest::gtest
    GTest::gtest_main
)

include(GoogleTest)

if(WIN32)
    add_custom_command(TARGET PasswordManager-tests POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            $<TARGET_RUNTIME_DLLS:PasswordManager-tests>
            $<TARGET_FILE_DIR:PasswordManager-tests>
        COMMAND_EXPAND_LISTS
        COMMENT "Copying runtime DLLs next to PasswordManager-tests")
endif()

gtest_discover_tests(PasswordManager-tests)

file(GLOB_RECURSE ALL_CXX_SOURCE_FILES
     CONFIGURE_DEPENDS
     ${CMAKE_SOURCE_DIR}/src/*.cpp
     ${CMAKE_SOURCE_DIR}/src/*.h)

find_program(CLANG_FORMAT_EXE clang-format)
find_program(CLANG_TIDY_EXE clang-tidy)

if(CLANG_FORMAT_EXE)
    add_custom_target(format
        COMMAND ${CLANG_FORMAT_EXE} -i --style=file ${ALL_CXX_SOURCE_FILES}
        COMMENT "Running clang-format on all source files"
        VERBATIM)

    add_custom_target(format-check
        COMMAND ${CLANG_FORMAT_EXE} --dry-run --Werror --style=file ${ALL_CXX_SOURCE_FILES}
        COMMENT "Checking clang-format compliance"
        VERBATIM)
else()
    message(WARNING "clang-format not found")
endif()

if(CLANG_TIDY_EXE)
    message(STATUS "clang-tidy found: ${CLANG_TIDY_EXE}")
else()
    message(WARNING "clang-tidy not found")
endif()