# Makefile for testing libopaque integration

VENDOR_DIR = ../../vendor/stef
LIBOPRF_DIR = $(VENDOR_DIR)/liboprf
LIBOPAQUE_DIR = $(VENDOR_DIR)/libopaque

CC = gcc
CFLAGS = -Wall -O2 -g -I$(LIBOPRF_DIR)/src -I$(LIBOPAQUE_DIR)/src
LDFLAGS = -L$(LIBOPRF_DIR)/src -L$(LIBOPRF_DIR)/src/noise_xk -L$(LIBOPAQUE_DIR)/src -lopaque -loprf -loprf-noiseXK -lsodium

# Test program
TEST_PROG = test_basic
TEST_SRC = test_basic.c

.PHONY: all clean build-deps test

all: build-deps $(TEST_PROG)

# Build dependencies
build-deps: build-liboprf build-libopaque

build-liboprf:
	@echo "Building liboprf..."
	cd $(LIBOPRF_DIR)/src && $(MAKE)

build-libopaque:
	@echo "Building libopaque..."
	cd $(LIBOPAQUE_DIR)/src && $(MAKE) OPRFHOME=$(LIBOPRF_DIR)/src

# Build test program
$(TEST_PROG): $(TEST_SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# Run test
test: $(TEST_PROG)
	LD_LIBRARY_PATH=$(LIBOPRF_DIR)/src:$(LIBOPRF_DIR)/src/noise_xk:$(LIBOPAQUE_DIR)/src ./$(TEST_PROG)

clean:
	rm -f $(TEST_PROG)
	cd $(LIBOPRF_DIR)/src && $(MAKE) clean
	cd $(LIBOPAQUE_DIR)/src && $(MAKE) clean

# Just compile without linking to check API compatibility
check-compile: $(TEST_SRC)
	$(CC) $(CFLAGS) -c $<
