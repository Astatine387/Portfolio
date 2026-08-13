cmake_minimum_required(VERSION 3.16)
project(PasswordManager VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

option(WARNINGS_AS_ERRORS "Treat compiler warnings as errors" OFF)

if(MSVC)
    set(BASE_WARNINGS
        /W4 /utf-8
        /external:anglebrackets
        /external:W0
        /Zc:__cplusplus /Zc:preprocessor
        /w14061  # enumerator not explicitly handled by a case label; mirrors -Wswitch-enum
        /w14062  # enumerator not handled, no default label; mirrors -Wswitch
        /w14263  # member function does not override any base class virtual
        /w14265  # class has virtual functions but destructor is not virtual
        /w14266  # virtual hidden by a derived overload; mirrors -Woverloaded-virtual
        /w14296  # expression is always true/false
        /w14388  # signed/unsigned mismatch; mirrors -Wsign-compare
        /w14640  # thread-unsafe static member initialization
        /w14826  # conversion is sign-extended
        /w14928  # illegal copy-initialization
        /w15038  # data member init out of order; mirrors -Wreorder
        /w15204  # virtual functions but trivial destructor is not virtual; 4265 misses this
        /w15262  # implicit fall-through; mirrors -Wimplicit-fallthrough
        /w15264  # unused 'const' variable; mirrors -Wunused-const-variable
        /w15267  # implicit copy ctor deprecated; mirrors -Wdeprecated-copy-dtor
    )
    set(STRICT_WARNINGS
        /w14365  # conversion, signed/unsigned mismatch
        /w14242  # conversion, possible loss of data
        /w14311  # pointer truncation
    )
    set(WARNINGS_AS_ERRORS_FLAG /WX)
    set(FRAME_BUDGET_FLAG "")
else()
    set(BASE_WARNINGS
        -Wall -Wextra
        -Wpedantic -Wshadow -Wnon-virtual-dtor -Woverloaded-virtual -Wsuggest-override
        -Wold-style-cast -Wformat=2 -Wzero-as-null-pointer-constant
        -Wundef -Wvla -Walloca -Wdate-time -Wmismatched-tags
        -Wextra-semi -Wswitch-enum -Wdeprecated-copy-dtor
        # GCC already gets this from -Wextra; Clang enables it at no -W level.
        -Wimplicit-fallthrough)
    set(STRICT_WARNINGS
        -Wsign-conversion -Wconversion
        -Wcast-qual -Wdouble-promotion)
    set(WARNINGS_AS_ERRORS_FLAG -Werror)
    set(FRAME_BUDGET_FLAG -Wframe-larger-than=16384)

    if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        # Clang rejects -Wunused-const-variable=2 outright and already covers the
        # plain form through -Wall, so the level stays on the GCC side.
        list(APPEND BASE_WARNINGS -Wduplicated-cond -Wduplicated-branches -Wlogical-op
                                  -Wredundant-tags -Wunused-const-variable=2)
        # Plain -Wcast-align never fires on x86-64; only the =strict form does.
        list(APPEND STRICT_WARNINGS -Wuseless-cast -Wcast-align=strict)
    elseif(CMAKE_CXX_COMPILER_ID MATCHES "^(Apple)?Clang$")
        list(APPEND BASE_WARNINGS -Wdocumentation -Wconditional-uninitialized
                                  -Wsuggest-destructor-override -Wshadow-all)
        # Clang rejects -Wcast-align=strict outright, so it keeps the plain form.
        list(APPEND STRICT_WARNINGS -Wcast-align)
    else()
        message(FATAL_ERROR
            "Warning tiers are not fully defined for compiler "
            "'${CMAKE_CXX_COMPILER_ID}'")
    endif()
endif()

add_library(project_warnings INTERFACE)
target_compile_options(project_warnings INTERFACE ${BASE_WARNINGS})

add_library(project_warnings_strict INTERFACE)
target_link_libraries(project_warnings_strict INTERFACE project_warnings)
target_compile_options(project_warnings_strict INTERFACE ${STRICT_WARNINGS})

if(WARNINGS_AS_ERRORS)
    target_compile_options(project_warnings INTERFACE ${WARNINGS_AS_ERRORS_FLAG})
endif()

message(STATUS "Warnings (base)   : ${BASE_WARNINGS}")
message(STATUS "Warnings (strict) : ${BASE_WARNINGS};${STRICT_WARNINGS}")

option(COVERAGE "Enable coverage reporting" OFF)

if(COVERAGE AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    message(STATUS "Coverage enabled")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} --coverage -fprofile-arcs -ftest-coverage")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} --coverage")
endif()

option(SANITIZE "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)

if(SANITIZE AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    message(STATUS "Sanitizers enabled (address, undefined)")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=address,undefined")
endif()

find_package(Qt6 REQUIRED COMPONENTS Core Gui Widgets)

find_package(OpenSSL 3.0 REQUIRED)

find_package(GTest CONFIG REQUIRED)

find_library(ARGON2_LIBRARY NAMES argon2)
find_path(ARGON2_INCLUDE_DIR argon2.h)

if(NOT ARGON2_LIBRARY OR NOT ARGON2_INCLUDE_DIR)
    message(FATAL_ERROR "Argon2 library not found")
endif()

find_library(SODIUM_LIBRARY NAMES sodium libsodium)
find_path(SODIUM_INCLUDE_DIR sodium.h)

if(NOT SODIUM_LIBRARY OR NOT SODIUM_INCLUDE_DIR)
    message(FATAL_ERROR "libsodium not found")
endif()

set(CORE_SOURCES
    src/core/aes_gcm.cpp
    src/core/aes_gcm_dec.cpp
    src/core/aes_gcm_enc.cpp
    src/core/entry.cpp
    src/core/secure_buffer.cpp
    src/core/secure_key.cpp
    src/core/vault.cpp
    src/core/vault_file.cpp
    src/core/vault_entry.cpp
    src/utils/password.cpp
    src/utils/platform.cpp
)

if(WIN32)
    list(APPEND CORE_SOURCES src/utils/platform_win32.cpp)
else()
    list(APPEND CORE_SOURCES src/utils/platform_linux.cpp)
endif()

set(CORE_HEADERS
    src/common/constants.h
    src/core/aes_gcm.h
    src/core/entry.h
    src/core/secure_buffer.h
    src/core/secure_key.h
    src/core/vault.h
    src/utils/password.h
    src/utils/platform.h
)

add_library(PasswordManager-core STATIC ${CORE_SOURCES} ${CORE_HEADERS})

target_include_directories(PasswordManager-core PUBLIC
    ${CMAKE_SOURCE_DIR}/src)

target_include_directories(PasswordManager-core SYSTEM PUBLIC
    ${ARGON2_INCLUDE_DIR}
    ${SODIUM_INCLUDE_DIR})

target_link_libraries(PasswordManager-core PUBLIC
    OpenSSL::Crypto
    ${ARGON2_LIBRARY}
    ${SODIUM_LIBRARY}
)

target_link_libraries(PasswordManager-core PRIVATE project_warnings_strict)

# Forward-looking stack budget; no frame here currently exceeds 1 KiB.
target_compile_options(PasswordManager-core PRIVATE ${FRAME_BUDGET_FLAG})

if(WIN32)
    target_link_libraries(PasswordManager-core PUBLIC bcrypt)
else()
    target_compile_definitions(PasswordManager-core PRIVATE _GNU_SOURCE)
endif()

set(GUI_SOURCES
    src/gui/change_pw_gui.cpp
    src/gui/clipboard.cpp
    src/gui/entry_gui.cpp
    src/gui/list_gui.cpp
    src/gui/login_gui.cpp
    src/gui/main_gui.cpp
    src/gui/password_gui.cpp
    src/gui/pw_line_edit.cpp
    src/gui/vault_interface.cpp
)

set(GUI_HEADERS
    src/gui/change_pw_gui.h
    src/gui/clipboard.h
    src/gui/entry_gui.h
    src/gui/entry_interface.h
    src/gui/list_gui.h
    src/gui/login_gui.h
    src/gui/main_gui.h
    src/gui/password_gui.h
    src/gui/pw_line_edit.h
    src/gui/vault_interface.h
)

add_library(PasswordManager-gui STATIC ${GUI_SOURCES} ${GUI_HEADERS})

target_link_libraries(PasswordManager-gui PUBLIC
    PasswordManager-core
    Qt6::Core
    Qt6::Gui
    Qt6::Widgets
)

target_link_libraries(PasswordManager-gui PRIVATE project_warnings)

add_executable(${PROJECT_NAME} src/common/main.cpp)
target_link_libraries(${PROJECT_NAME} PRIVATE PasswordManager-gui project_warnings)

enable_testing()

set(TEST_SOURCES
    src/tests/aes_gcm_test.cpp
    src/tests/entry_test.cpp
    src/tests/password_test.cpp
    src/tests/secure_buffer_test.cpp
    src/tests/secure_key_test.cpp
    src/tests/utils_test.cpp
    src/tests/vault_entry_test.cpp
    src/tests/vault_file_test.cpp
)

add_executable(PasswordManager-tests ${TEST_SOURCES})

target_link_libraries(PasswordManager-tests PRIVATE
    PasswordManager-core
    GTest::gtest
    GTest::gtest_main
    project_warnings_strict
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