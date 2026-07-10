cmake_minimum_required(VERSION 3.16)
project(DigitalLogicSimulator VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ============================================================
# Build Options
# ============================================================

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

# ============================================================
# Dependencies
# ============================================================

find_package(GTest CONFIG REQUIRED)
find_package(Threads REQUIRED)
find_package(benchmark CONFIG QUIET)

# ============================================================
# Core Library
# ============================================================

set(CORE_SOURCES
    src/core/kernel.cpp
    src/core/logic4.cpp
    src/core/netlist.cpp
)

set(CORE_HEADERS
    src/core/kernel.h
    src/core/logic4.h
    src/core/netlist.h
)

add_library(${PROJECT_NAME}-core STATIC ${CORE_SOURCES} ${CORE_HEADERS})

target_include_directories(${PROJECT_NAME}-core PUBLIC
    ${CMAKE_SOURCE_DIR}/src
)

# ============================================================
# Parser Library
# ============================================================

set(PARSER_SOURCES
    src/parser/vcd_writer.cpp
)

set(PARSER_HEADERS
    src/parser/vcd_writer.h
)

add_library(${PROJECT_NAME}-parser STATIC ${PARSER_SOURCES} ${PARSER_HEADERS})

target_link_libraries(${PROJECT_NAME}-parser PUBLIC
    ${PROJECT_NAME}-core
)

# ============================================================
# CLI Executable
# ============================================================

add_executable(${PROJECT_NAME} src/common/main.cpp)

target_link_libraries(${PROJECT_NAME} PRIVATE
    ${PROJECT_NAME}-parser
)

# ============================================================
# Tests
# ============================================================

enable_testing()

set(TEST_SOURCES
    src/tests/kernel_test.cpp
    src/tests/logic4_test.cpp
    src/tests/netlist_test.cpp
    src/tests/vcd_writer_test.cpp
)

add_executable(${PROJECT_NAME}-tests ${TEST_SOURCES})

target_link_libraries(${PROJECT_NAME}-tests PRIVATE
    ${PROJECT_NAME}-core
    ${PROJECT_NAME}-parser
    GTest::gtest
    GTest::gtest_main
    Threads::Threads
)

include(GoogleTest)

if(WIN32)
    add_custom_command(TARGET ${PROJECT_NAME}-tests POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            $<TARGET_RUNTIME_DLLS:${PROJECT_NAME}-tests>
            $<TARGET_FILE_DIR:${PROJECT_NAME}-tests>
        COMMAND_EXPAND_LISTS
    )
endif()

gtest_discover_tests(${PROJECT_NAME}-tests)

# ============================================================
# Benchmark (optional)
# ============================================================

if(benchmark_FOUND)
    set(BENCH_SOURCES
        src/benchmark/benchmark.cpp
    )

    add_executable(${PROJECT_NAME}-bench ${BENCH_SOURCES})

    target_link_libraries(${PROJECT_NAME}-bench PRIVATE
        ${PROJECT_NAME}-core
        benchmark::benchmark
        benchmark::benchmark_main
    )

    if(WIN32)
        add_custom_command(TARGET ${PROJECT_NAME}-bench POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                $<TARGET_RUNTIME_DLLS:${PROJECT_NAME}-bench>
                $<TARGET_FILE_DIR:${PROJECT_NAME}-bench>
            COMMAND_EXPAND_LISTS
        )
    endif()
endif()

# ============================================================
# Formatting and Static Analysis
# ============================================================

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