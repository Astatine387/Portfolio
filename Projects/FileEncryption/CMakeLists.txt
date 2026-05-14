cmake_minimum_required(VERSION 3.16)
project(FileEncryption VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

# Converage
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
    src/Core/aes_gcm.cpp
    src/Core/aes_gcm_dec.cpp
    src/Core/aes_gcm_enc.cpp
    src/Core/worker.cpp
    src/GUI/input_gui.cpp
    src/GUI/main_gui.cpp
    src/GUI/progress_gui.cpp
    src/GUI/mode_button.cpp
    src/GUI/pw_line_edit.cpp
    src/Utils/password.cpp
    src/Utils/library.cpp
)

set(HEADERS
    src/Common/constants.h
    src/Core/aes_gcm.h
    src/Core/worker.h
    src/GUI/input_gui.h
    src/GUI/main_gui.h
    src/GUI/progress_gui.h
    src/GUI/mode_button.h
    src/GUI/pw_line_edit.h
    src/Utils/library.h
    src/Utils/password.h
)

add_library(FileEncryption-lib STATIC ${LIB_SOURCES} ${HEADERS})

target_include_directories(FileEncryption-lib PUBLIC
    ${CMAKE_SOURCE_DIR}/src
    ${ARGON2_INCLUDE_DIR}
)

target_link_libraries(FileEncryption-lib PUBLIC
    Qt6::Core
    Qt6::Gui
    Qt6::Widgets
    OpenSSL::Crypto
    ${ARGON2_LIBRARY}
)

if(WIN32)
    target_link_libraries(FileEncryption-lib PUBLIC bcrypt)
endif()

add_executable(${PROJECT_NAME} src/Common/main.cpp)
target_link_libraries(${PROJECT_NAME} PRIVATE FileEncryption-lib)

enable_testing()

set(TEST_SOURCES
    src/Tests/aes_gcm_test.cpp
    src/Tests/password_test.cpp
    src/Tests/utils_test.cpp
)

add_executable(FileEncryption-tests ${TEST_SOURCES})

target_link_libraries(FileEncryption-tests PRIVATE
    FileEncryption-lib
    GTest::gtest
    GTest::gtest_main
)

include(GoogleTest)

if(WIN32)
    add_custom_command(TARGET FileEncryption-tests POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            $<TARGET_RUNTIME_DLLS:FileEncryption-tests>
            $<TARGET_FILE_DIR:FileEncryption-tests>
        COMMAND_EXPAND_LISTS
        COMMENT "Copying runtime DLLs next to FileEncryption-tests")
endif()

gtest_discover_tests(FileEncryption-tests)

find_package(benchmark CONFIG QUIET)

if(benchmark_FOUND)
    set(BENCH_SOURCES
        src/Benchmark/benchmark.cpp
    )

    add_executable(FileEncryption-bench ${BENCH_SOURCES})
    target_link_libraries(FileEncryption-bench PRIVATE
        FileEncryption-lib
        benchmark::benchmark
        benchmark::benchmark_main
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