cmake_minimum_required(VERSION 3.10)
project(MessagingProtocol)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Add compiler flags for debugging and sanitizers
set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -Wall -Wextra")
set(CMAKE_CXX_FLAGS_ASAN "-g -O1 -fsanitize=address -fno-omit-frame-pointer")
set(CMAKE_CXX_FLAGS_MSAN "-g -O1 -fsanitize=memory -fno-omit-frame-pointer")
set(CMAKE_CXX_FLAGS_UBSAN "-g -O1 -fsanitize=undefined")

# Library source files
set(LIB_SOURCES
    lib/protocol.cpp
)

# Create the protocol library
add_library(simple_protocol ${LIB_SOURCES})
target_include_directories(simple_protocol PUBLIC lib)

# Example executables
add_executable(demo examples/demo.cpp)
target_link_libraries(demo simple_protocol)

# Test executable
add_executable(test_protocol tests/test_protocol.cpp)
target_link_libraries(test_protocol simple_protocol)

# Fuzzing targets (require Clang with libFuzzer)
# if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
#     add_executable(fuzz_deserialize # fuzzing/fuzz_deserialize.cpp)
#     target_link_libraries(fuzz_deserialize simple_protocol)
#     target_compile_options(fuzz_deserialize PRIVATE # -fsanitize=fuzzer,address)
#     target_link_options(fuzz_deserialize PRIVATE # -fsanitize=fuzzer)
#
#     add_executable(fuzz_roundtrip fuzzing/fuzz_roundtrip.cpp)
#     target_link_libraries(fuzz_roundtrip simple_protocol)
#     target_compile_options(fuzz_roundtrip PRIVATE # -fsanitize=fuzzer,address)
#     target_link_options(fuzz_roundtrip PRIVATE # -fsanitize=fuzzer)
# endif()

# Custom targets for different sanitizer builds
add_custom_target(build_asan
    COMMAND ${CMAKE_COMMAND} -DCMAKE_BUILD_TYPE=ASAN -DCMAKE_CXX_FLAGS="${CMAKE_CXX_FLAGS_ASAN}" ${CMAKE_SOURCE_DIR}
    COMMAND make
    COMMENT "Building with AddressSanitizer"
)

add_custom_target(build_ubsan
    COMMAND ${CMAKE_COMMAND} -DCMAKE_BUILD_TYPE=UBSAN -DCMAKE_CXX_FLAGS="${CMAKE_CXX_FLAGS_UBSAN}" ${CMAKE_SOURCE_DIR}
    COMMAND make
    COMMENT "Building with UndefinedBehaviorSanitizer"
)
