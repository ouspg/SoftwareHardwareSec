# Makefile for our simple protocol
# Provides convenient targets for building and testing, including some sanitizer examples

.PHONY: all clean test demo debug asan msan ubsan help

# Default target
all: build
	@cd build && make -j$(shell nproc 2>/dev/null || echo 4)

# Create build directory and configure
build:
	@mkdir -p build
	@cd build &&  cmake ..
	# @cd build &&  cmake -DCMAKE_CXX_COMPILER=/opt/homebrew/opt/llvm/bin/clang++ ..

# Clean all build directories
clean:
	@echo "Cleaning build directories..."
	@rm -rf build build-asan build-msan build-ubsan build-debug

# Run basic tests
test: all
	@echo "Running basic tests..."
	@./build/test_protocol

# Run demo
demo: all
	@echo "Running demo..."
	@./build/demo

# Debug build
debug:
	@echo "Building debug version..."
	@mkdir -p build-debug
	@cd build-debug && cmake -DCMAKE_BUILD_TYPE=Debug -DCMAKE_CXX_FLAGS="-g -O0 -Wall -Wextra" ..
	@cd build-debug && make -j$(shell nproc 2>/dev/null || echo 4)

# AddressSanitizer build
asan:
	@echo "Building with AddressSanitizer..."
	@mkdir -p build-asan
	@cd build-asan && cmake -DCMAKE_BUILD_TYPE=Debug -DCMAKE_CXX_FLAGS="-fsanitize=address -g -O1 -fno-omit-frame-pointer" ..
	@cd build-asan && make -j$(shell nproc 2>/dev/null || echo 4)

# MemorySanitizer build (requires clang)
msan:
	@echo "Building with MemorySanitizer..."
	@mkdir -p build-msan
	@cd build-msan && CC=clang CXX=clang++ cmake -DCMAKE_BUILD_TYPE=Debug -DCMAKE_CXX_FLAGS="-fsanitize=memory -g -O1 -fno-omit-frame-pointer" ..
	@cd build-msan && make -j$(shell nproc 2>/dev/null || echo 4)

# UndefinedBehaviorSanitizer build
ubsan:
	@echo "Building with UndefinedBehaviorSanitizer..."
	@mkdir -p build-ubsan
	@cd build-ubsan && cmake -DCMAKE_BUILD_TYPE=Debug -DCMAKE_CXX_FLAGS="-fsanitize=undefined -g -O1" ..
	@cd build-ubsan && make -j$(shell nproc 2>/dev/null || echo 4)

# Test with AddressSanitizer (will show potential memory bugs)
test-asan: asan
	@echo "Running tests with AddressSanitizer..."
	@./build-asan/test_protocol

# Run demo with AddressSanitizer (will show potential memory bugs)
demo-asan: asan
	@echo "Running demo with AddressSanitizer..."
	@./build-asan/demo

# Test with UndefinedBehaviorSanitizer
test-ubsan: ubsan
	@echo "Running tests with UndefinedBehaviorSanitizer..."
	@UBSAN_OPTIONS=halt_on_error=1 ./build-ubsan/test_protocol

# Run demo with UndefinedBehaviorSanitizer
demo-ubsan: ubsan
	@echo "Running demo with UndefinedBehaviorSanitizer..."
	@UBSAN_OPTIONS=halt_on_error=1 ./build-ubsan/demo
#
# Run demo with MemorySanitizer
demo-msan: msan
	@echo "Running demo with MemorySanitizer..."
	@./build-msan/demo

# Run test with MemorySanitizer
test-msan: msan
	@echo "Running tests with MemorySanitizer..."
	@./build-msan/test_protocol

# Run with Valgrind (if available)
valgrind: all
	@echo "Running with Valgrind..."
	@if command -v valgrind >/dev/null 2>&1; then \
		valgrind --leak-check=full --track-origins=yes --error-exitcode=1 ./build/demo; \
	else \
		echo "Valgrind not found." >&2; exit 1; \
	fi

# Revert patches
unpatch:
	@echo "Reverting all patches..."
	@git checkout -- lib/protocol.cpp


# TODO missing files
# Create a simple fuzz target
# fuzz-build:
# 	@echo "Building fuzzing targets with Clang..."
# 	@set -e; if command -v clang++ >/dev/null 2>&1; then \
# 		clang++ -std=c++17 -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=undefined -g -O1 -I lib \
# 			fuzzing/fuzz_deserialize.cpp lib/protocol.cpp -o fuzz_deserialize; \
# 		clang++ -std=c++17 -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=undefined -g -O1 -I lib \
# 			fuzzing/fuzz_roundtrip.cpp lib/protocol.cpp -o fuzz_roundtrip; \
# 		echo "Fuzzing targets built: fuzz_deserialize, fuzz_roundtrip"; \
# 	else \
# 		echo "Clang not found." >&2; exit 1; \
# 	fi

# fuzz-run:
# 	@echo "Running fuzzing target..."
# 	@if [ -f ./fuzz_deserialize ]; then \
# 		echo "Running deserialization fuzzer for 60 seconds..."; \
# 		./fuzz_deserialize -max_total_time=60; \
# 	else \
# 		echo "Run 'make fuzz-build' first" >&2; exit 1; \
# 	fi
