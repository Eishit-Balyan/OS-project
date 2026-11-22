# ==============================================================================
# Warden - Makefile
# Compiler flags: C++17, strict warnings, POSIX threads, OpenSSL crypto
# Supported targets: all (default), clean, debug, tsan, test-formats, test-queue, test
# ==============================================================================

CXX      ?= g++
CXXFLAGS ?= -std=c++17 -Wall -Wextra -pthread
CPPFLAGS ?= -Iinclude
LDFLAGS  ?= -pthread
LDLIBS   ?= -lssl -lcrypto

TARGET   := warden
BUILD_DIR := build
SRC_DIR   := src

SRCS     := $(wildcard $(SRC_DIR)/*.cpp)
OBJS     := $(patsubst $(SRC_DIR)/%.cpp,$(BUILD_DIR)/%.o,$(SRCS))
MODULE_OBJS := $(filter-out $(BUILD_DIR)/main.o, $(OBJS))

TEST_FORMATS_BIN := $(BUILD_DIR)/test_formats
TEST_QUEUE_BIN   := $(BUILD_DIR)/test_queue

# Default target
.PHONY: all
all: $(TARGET)

# Link the executable
$(TARGET): $(OBJS)
	$(CXX) $(OBJS) $(LDFLAGS) $(LDLIBS) -o $@

# Compile source files into object files
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.cpp | $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@

# Create build directory
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Debug build target (-g -O0)
.PHONY: debug
debug: CXXFLAGS += -g -O0
debug: $(TARGET)

# ThreadSanitizer build target (-fsanitize=thread -g)
.PHONY: tsan
tsan: CXXFLAGS += -fsanitize=thread -g
tsan: LDFLAGS  += -fsanitize=thread
tsan: $(TARGET)

# Target to build and execute data format tests
.PHONY: test-formats
test-formats: $(TEST_FORMATS_BIN)
	./$(TEST_FORMATS_BIN)

$(TEST_FORMATS_BIN): tests/test_formats.cpp $(BUILD_DIR)/common.o | $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) tests/test_formats.cpp $(BUILD_DIR)/common.o $(LDFLAGS) $(LDLIBS) -o $@

# Target to build and execute concurrent queue stress test
.PHONY: test-queue
test-queue: $(TEST_QUEUE_BIN)
	./$(TEST_QUEUE_BIN)

$(TEST_QUEUE_BIN): tests/test_queue.cpp $(MODULE_OBJS) | $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) tests/test_queue.cpp $(MODULE_OBJS) $(LDFLAGS) $(LDLIBS) -o $@

# Target to run all bash integration test scripts
.PHONY: test
test: all test-formats test-queue
	bash tests/run_all.sh

# Clean build artifacts
.PHONY: clean
clean:
	rm -rf $(BUILD_DIR) $(TARGET)
