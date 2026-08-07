cmake_minimum_required(VERSION 3.16)
project(FileEncryption VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

option(WARNINGS_AS_ERRORS "Treat compiler warnings as errors" OFF)

if(MSVC)
    set(BASE_WARNINGS
        /W4 /utf-8
        /external:anglebrackets
        /external:W0)
    set(STRICT_WARNINGS /w14365)
    set(WARNINGS_AS_ERRORS_FLAG /WX)
else()
    set(BASE_WARNINGS
        -Wall -Wextra
        -Wpedantic -Wshadow -Wnon-virtual-dtor -Woverloaded-virtual -Wsuggest-override
        -Wold-style-cast -Wformat=2 -Wimplicit-fallthrough -Wzero-as-null-pointer-constant
        -Wundef -Wvla -Walloca -Wdate-time -Wnull-dereference -Wmismatched-tags
        -Wextra-semi)
    set(STRICT_WARNINGS
        -Wsign-conversion -Wconversion
        -Wcast-qual -Wcast-align -Wdouble-promotion)
    set(WARNINGS_AS_ERRORS_FLAG -Werror)

    if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        list(APPEND BASE_WARNINGS -Wduplicated-cond -Wduplicated-branches -Wlogical-op -Wredundant-tags)
        list(APPEND STRICT_WARNINGS -Wuseless-cast)
    elseif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        list(APPEND BASE_WARNINGS -Wthread-safety -Wdocumentation -Wconditional-uninitialized)
    endif()
endif()

if(NOT BASE_WARNINGS OR NOT STRICT_WARNINGS OR NOT WARNINGS_AS_ERRORS_FLAG)
    message(FATAL_ERROR
        "Warning tiers are not fully defined for compiler "
        "'${CMAKE_CXX_COMPILER_ID}'")
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
option(THREAD_SANITIZE "Enable ThreadSanitizer" OFF)

if(SANITIZE AND THREAD_SANITIZE)
    message(FATAL_ERROR "SANITIZE and THREAD_SANITIZE are mutually exclusive; enable only one")
endif()

if(SANITIZE AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    message(STATUS "Sanitizers enabled (address, undefined)")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=address,undefined")
endif()

if(THREAD_SANITIZE AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    message(STATUS "ThreadSanitizer enabled")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=thread -fno-omit-frame-pointer")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=thread")
endif()

find_package(Qt6 REQUIRED COMPONENTS Core Gui Widgets)

find_package(OpenSSL 3.0 REQUIRED)

find_package(GTest CONFIG REQUIRED)

find_package(Threads REQUIRED)

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
    src/core/crypto_worker.cpp
    src/core/secure_key.cpp
    src/utils/password.cpp
)

if(WIN32)
    list(APPEND CORE_SOURCES src/utils/platform_win32.cpp)
else()
    list(APPEND CORE_SOURCES src/utils/platform_linux.cpp)
endif()

set(CORE_HEADERS
    src/common/constants.h
    src/core/aes_gcm.h
    src/core/crypto_worker.h
    src/core/secure_key.h
    src/utils/mutex.h
    src/utils/password.h
    src/utils/platform.h
    src/utils/thread_annotations.h
)

add_library(FileEncryption-core STATIC ${CORE_SOURCES} ${CORE_HEADERS})

target_include_directories(FileEncryption-core PUBLIC
    ${CMAKE_SOURCE_DIR}/src)

target_include_directories(FileEncryption-core SYSTEM PUBLIC
    ${ARGON2_INCLUDE_DIR}
    ${SODIUM_INCLUDE_DIR})

target_link_libraries(FileEncryption-core PUBLIC
    OpenSSL::Crypto
    ${ARGON2_LIBRARY}
    ${SODIUM_LIBRARY}
)

target_link_libraries(FileEncryption-core PRIVATE project_warnings_strict)

if(WIN32)
    target_link_libraries(FileEncryption-core PUBLIC bcrypt)
else()
    target_compile_definitions(FileEncryption-core PRIVATE _GNU_SOURCE)
endif()

set(GUI_SOURCES
    src/gui/crypto_wrapper.cpp
    src/gui/input_gui.cpp
    src/gui/main_gui.cpp
    src/gui/progress_gui.cpp
    src/gui/mode_button.cpp
    src/gui/pw_line_edit.cpp
)

set(GUI_HEADERS
    src/gui/crypto_wrapper.h
    src/gui/input_gui.h
    src/gui/main_gui.h
    src/gui/progress_gui.h
    src/gui/mode_button.h
    src/gui/pw_line_edit.h
)

add_library(FileEncryption-gui STATIC ${GUI_SOURCES} ${GUI_HEADERS})

target_link_libraries(FileEncryption-gui PUBLIC
    FileEncryption-core
    Qt6::Core
    Qt6::Gui
    Qt6::Widgets
)

target_link_libraries(FileEncryption-gui PRIVATE project_warnings)

add_executable(${PROJECT_NAME} src/common/main.cpp)
target_link_libraries(${PROJECT_NAME} PRIVATE FileEncryption-gui project_warnings)

enable_testing()

set(TEST_SOURCES
    src/tests/aes_gcm_test.cpp
    src/tests/crypto_worker_test.cpp
    src/tests/password_test.cpp
    src/tests/secure_key_test.cpp
    src/tests/utils_test.cpp
)

add_executable(FileEncryption-tests ${TEST_SOURCES})

target_link_libraries(FileEncryption-tests PRIVATE
    FileEncryption-core
    GTest::gtest
    GTest::gtest_main
    Threads::Threads
    project_warnings_strict
)

include(GoogleTest)

if(WIN32)
    add_custom_command(TARGET FileEncryption-tests POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            $<TARGET_RUNTIME_DLLS:FileEncryption-tests>
            $<TARGET_FILE_DIR:FileEncryption-tests>
        COMMAND_EXPAND_LISTS
    )
endif()

gtest_discover_tests(FileEncryption-tests)

find_package(benchmark CONFIG QUIET)

if(benchmark_FOUND)
    set(BENCH_SOURCES
        src/benchmark/benchmark.cpp
    )

    add_executable(FileEncryption-bench ${BENCH_SOURCES})
    target_link_libraries(FileEncryption-bench PRIVATE
        FileEncryption-core
        benchmark::benchmark
        benchmark::benchmark_main
        project_warnings_strict
    )
endif()

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