#!/bin/bash

# Performance Benchmark Script for Arkfile Phase 4
# This script establishes performance baselines for large file operations

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
TEST_DIR="/tmp/arkfile-benchmark-$$"
RESULTS_FILE="benchmark-results-$(date +%Y%m%d-%H%M%S).txt"

# File sizes for testing
SIZES=(
    "1M"
    "10M" 
    "100M"
    "500M"
    "1G"
)

echo -e "${BLUE}⚡ Arkfile Performance Benchmark Suite${NC}"
echo "================================================"
echo "Test directory: ${TEST_DIR}"
echo "Results file: ${RESULTS_FILE}"
echo "Hardware: $(uname -m) $(nproc) cores"
echo "Memory: $(free -h | grep ^Mem | awk '{print $2}')"
echo "Date: $(date)"
echo "================================================"
echo

# Create test directory
mkdir -p "${TEST_DIR}"
cd "${TEST_DIR}"

# Initialize results file
{
    echo "Arkfile Performance Benchmark Results"
    echo "======================================"
    echo "Date: $(date)"
    echo "Hardware: $(uname -m) $(nproc) cores"
    echo "Memory: $(free -h | grep ^Mem | awk '{print $2}')"
    echo "Go Version: $(go version)"
    echo "======================================"
    echo
} > "${RESULTS_FILE}"

# Function to run crypto benchmarks
run_crypto_benchmarks() {
    echo -e "${BLUE}🔐 Running cryptographic benchmarks...${NC}"
    
    echo "Crypto Benchmarks" >> "${RESULTS_FILE}"
    echo "-----------------" >> "${RESULTS_FILE}"
    
    # Benchmark Argon2ID across different profiles
    echo -e "${YELLOW}Benchmarking Argon2ID profiles...${NC}"
    echo "Argon2ID Profile Benchmarks:" >> "${RESULTS_FILE}"
    
    cd "${OLDPWD}"
    go test -bench=BenchmarkArgon2ID -benchmem -benchtime=5s ./crypto/... 2>&1 | tee -a "${TEST_DIR}/${RESULTS_FILE}"
    
    # Benchmark AES-GCM operations
    echo -e "${YELLOW}Benchmarking AES-GCM operations...${NC}"
    echo "AES-GCM Benchmarks:" >> "${TEST_DIR}/${RESULTS_FILE}"
    
    go test -bench=BenchmarkAESGCM -benchmem -benchtime=5s ./crypto/... 2>&1 | tee -a "${TEST_DIR}/${RESULTS_FILE}"
    
    # Benchmark OPAQUE operations
    echo -e "${YELLOW}Benchmarking OPAQUE operations...${NC}"
    echo "OPAQUE Benchmarks:" >> "${TEST_DIR}/${RESULTS_FILE}"
    
    go test -bench=BenchmarkOPAQUE -benchmem -benchtime=3s ./auth/... 2>&1 | tee -a "${TEST_DIR}/${RESULTS_FILE}"
    
    cd "${TEST_DIR}"
    
    echo "" >> "${RESULTS_FILE}"
}

# Function to create test files
create_test_files() {
    echo -e "${BLUE}📁 Creating test files...${NC}"
    
    for size in "${SIZES[@]}"; do
        filename="testfile_${size}.bin"
        echo -e "${YELLOW}Creating ${size} test file: ${filename}${NC}"
        
        if [[ "${size}" == "1G" ]]; then
            # For 1GB file, show progress
            dd if=/dev/urandom of="${filename}" bs=1M count=1024 status=progress 2>/dev/null
        else
            # Convert size format for dd
            if [[ "${size}" == *"M" ]]; then
                count=${size%M}
                bs="1M"
            elif [[ "${size}" == *"G" ]]; then
                count=${size%G}
                bs="1G"
            fi
            dd if=/dev/urandom of="${filename}" bs=${bs} count=${count} 2>/dev/null
        fi
        
        echo -e "${GREEN}✅ Created ${filename} ($(ls -lh ${filename} | awk '{print $5}'))${NC}"
    done
}

# Function to benchmark file encryption
benchmark_file_encryption() {
    echo -e "${BLUE}🔒 Benchmarking file encryption...${NC}"
    
    echo "File Encryption Benchmarks" >> "${RESULTS_FILE}"
    echo "---------------------------" >> "${RESULTS_FILE}"
    
    local password="BenchmarkPassword123!"
    
    for size in "${SIZES[@]}"; do
        local filename="testfile_${size}.bin"
        local encrypted_file="${filename}.encrypted"
        
        echo -e "${YELLOW}Encrypting ${size} file...${NC}"
        
        # Time the encryption process
        local start_time=$(date +%s.%N)
        
        # Build and run a simple encryption test
        cd "${OLDPWD}"
        cat > /tmp/encrypt_test.go << 'EOF'
package main

import (
    "fmt"
    "io/ioutil"
    "os"
    "time"
    
    "github.com/84adam/arkfile/crypto"
)

func main() {
    if len(os.Args) != 4 {
        fmt.Println("Usage: encrypt_test <input> <output> <password>")
        os.Exit(1)
    }
    
    inputFile := os.Args[1]
    outputFile := os.Args[2] 
    password := os.Args[3]
    
    // Read file
    data, err := ioutil.ReadFile(inputFile)
    if err != nil {
        fmt.Printf("Error reading file: %v\n", err)
        os.Exit(1)
    }
    
    // Generate salt
    salt := crypto.GenerateSalt()
    
    // Time encryption
    start := time.Now()
    
    // Derive key using Argon2ID
    key := crypto.DeriveKey(password, salt, crypto.DeviceBalanced)
    
    // Encrypt using AES-GCM
    encrypted, err := crypto.EncryptAESGCM(data, key)
    if err != nil {
        fmt.Printf("Error encrypting: %v\n", err)
        os.Exit(1)
    }
    
    duration := time.Since(start)
    
    // Write encrypted file
    err = ioutil.WriteFile(outputFile, encrypted, 0644)
    if err != nil {
        fmt.Printf("Error writing file: %v\n", err)
        os.Exit(1)
    }
    
    // Print timing information
    originalSize := len(data)
    encryptedSize := len(encrypted)
    throughput := float64(originalSize) / duration.Seconds() / 1024 / 1024 // MB/s
    
    fmt.Printf("Size: %d bytes\n", originalSize)
    fmt.Printf("Encrypted Size: %d bytes\n", encryptedSize)
    fmt.Printf("Duration: %v\n", duration)
    fmt.Printf("Throughput: %.2f MB/s\n", throughput)
}
EOF
        
        # Try to compile and run the encryption test
        if go build -o /tmp/encrypt_test /tmp/encrypt_test.go 2>/dev/null; then
            cd "${TEST_DIR}"
            result=$(/tmp/encrypt_test "${filename}" "${encrypted_file}" "${password}" 2>&1)
            echo "${size}: ${result}" >> "${RESULTS_FILE}"
            echo -e "${GREEN}✅ ${size}: $(echo "${result}" | grep "Throughput" | head -1)${NC}"
        else
            cd "${TEST_DIR}"
            # Fallback: just measure file copy time as baseline
            start_time=$(date +%s.%N)
            cp "${filename}" "${encrypted_file}"
            end_time=$(date +%s.%N)
            duration=$(echo "${end_time} - ${start_time}" | bc)
            file_size=$(stat -c%s "${filename}")
            throughput=$(echo "scale=2; ${file_size} / ${duration} / 1024 / 1024" | bc)
            echo "${size}: Fallback copy test - Duration: ${duration}s, Throughput: ${throughput} MB/s" >> "${RESULTS_FILE}"
            echo -e "${YELLOW}⚠️  ${size}: Fallback copy test - ${throughput} MB/s${NC}"
        fi
    done
    
    echo "" >> "${RESULTS_FILE}"
}

# Function to benchmark storage operations
benchmark_storage_operations() {
    echo -e "${BLUE}💾 Benchmarking storage operations...${NC}"
    
    echo "Storage I/O Benchmarks" >> "${RESULTS_FILE}"
    echo "----------------------" >> "${RESULTS_FILE}"
    
    for size in "${SIZES[@]}"; do
        local filename="testfile_${size}.bin"
        
        echo -e "${YELLOW}Testing I/O for ${size} file...${NC}"
        
        # Read benchmark
        echo "Reading ${filename}..." >> "${RESULTS_FILE}"
        start_time=$(date +%s.%N)
        cat "${filename}" > /dev/null
        end_time=$(date +%s.%N)
        read_duration=$(echo "${end_time} - ${start_time}" | bc)
        
        # Write benchmark
        echo "Writing copy of ${filename}..." >> "${RESULTS_FILE}"
        start_time=$(date +%s.%N)
        cp "${filename}" "${filename}.copy"
        end_time=$(date +%s.%N)
        write_duration=$(echo "${end_time} - ${start_time}" | bc)
        
        file_size=$(stat -c%s "${filename}")
        read_throughput=$(echo "scale=2; ${file_size} / ${read_duration} / 1024 / 1024" | bc)
        write_throughput=$(echo "scale=2; ${file_size} / ${write_duration} / 1024 / 1024" | bc)
        
        echo "${size}: Read: ${read_throughput} MB/s, Write: ${write_throughput} MB/s" >> "${RESULTS_FILE}"
        echo -e "${GREEN}✅ ${size}: Read: ${read_throughput} MB/s, Write: ${write_throughput} MB/s${NC}"
        
        # Clean up copy
        rm -f "${filename}.copy"
    done
    
    echo "" >> "${RESULTS_FILE}"
}

# Function to benchmark memory usage
benchmark_memory_usage() {
    echo -e "${BLUE}🧠 Benchmarking memory usage...${NC}"
    
    echo "Memory Usage Analysis" >> "${RESULTS_FILE}"
    echo "--------------------" >> "${RESULTS_FILE}"
    
    # Get baseline memory usage
    baseline_mem=$(free -m | grep ^Mem | awk '{print $3}')
    echo "Baseline memory usage: ${baseline_mem} MB" >> "${RESULTS_FILE}"
    
    echo "Process memory monitoring would require application integration" >> "${RESULTS_FILE}"
    echo "Manual testing recommended for detailed memory profiling" >> "${RESULTS_FILE}"
    echo "" >> "${RESULTS_FILE}"
}

# Function to generate summary report
generate_summary() {
    echo -e "${BLUE}📊 Generating performance summary...${NC}"
    
    echo "Performance Summary" >> "${RESULTS_FILE}"
    echo "==================" >> "${RESULTS_FILE}"
    echo "Test completed: $(date)" >> "${RESULTS_FILE}"
    
    # Find 1GB results if available
    if grep -q "1G:" "${RESULTS_FILE}"; then
        echo "" >> "${RESULTS_FILE}"
        echo "1GB File Performance Highlights:" >> "${RESULTS_FILE}"
        grep "1G:" "${RESULTS_FILE}" | head -5 >> "${RESULTS_FILE}"
    fi
    
    echo "" >> "${RESULTS_FILE}"
    echo "Hardware specifications:" >> "${RESULTS_FILE}"
    echo "- CPU: $(lscpu | grep "Model name" | cut -d: -f2 | sed 's/^ *//')" >> "${RESULTS_FILE}"
    echo "- Cores: $(nproc)" >> "${RESULTS_FILE}"
    echo "- Memory: $(free -h | grep ^Mem | awk '{print $2}')" >> "${RESULTS_FILE}"
    echo "- Storage: $(df -h . | tail -1 | awk '{print $2 " (" $3 " used)"}')" >> "${RESULTS_FILE}"
    
    echo "" >> "${RESULTS_FILE}"
    echo "Recommended optimizations based on results:" >> "${RESULTS_FILE}"
    echo "- Monitor actual performance in production environment" >> "${RESULTS_FILE}"
    echo "- Consider chunked upload/download for files >100MB" >> "${RESULTS_FILE}"
    echo "- Implement progress indicators for files >10MB" >> "${RESULTS_FILE}"
    echo "- Test with actual MinIO backend for realistic I/O performance" >> "${RESULTS_FILE}"
}

# Main execution flow
main() {
    echo -e "${BLUE}Starting comprehensive performance benchmark...${NC}"
    echo
    
    # Check available disk space
    available_space=$(df . | tail -1 | awk '{print $4}')
    required_space=2000000  # ~2GB in KB
    
    if [ "${available_space}" -lt "${required_space}" ]; then
        echo -e "${RED}❌ Insufficient disk space. Need ~2GB for testing.${NC}"
        exit 1
    fi
    
    # Run benchmarks
    run_crypto_benchmarks
    create_test_files
    benchmark_file_encryption
    benchmark_storage_operations
    benchmark_memory_usage
    generate_summary
    
    # Display results
    echo
    echo -e "${GREEN}🎉 Performance benchmark completed!${NC}"
    echo -e "${BLUE}Results saved to: ${TEST_DIR}/${RESULTS_FILE}${NC}"
    echo
    echo -e "${YELLOW}Key findings:${NC}"
    
    if [ -f "${RESULTS_FILE}" ]; then
        echo "----------------------------------------"
        cat "${RESULTS_FILE}" | tail -20
        echo "----------------------------------------"
    fi
    
    echo
    echo -e "${BLUE}To view complete results:${NC}"
    echo "cat ${TEST_DIR}/${RESULTS_FILE}"
    echo
    echo -e "${BLUE}To clean up test files:${NC}"
    echo "rm -rf ${TEST_DIR}"
}

# Cleanup function
cleanup() {
    echo
    echo -e "${YELLOW}Cleaning up...${NC}"
    cd "${OLDPWD}"
    # Remove test directory and all test files
    if [ -d "${TEST_DIR}" ]; then
        rm -rf "${TEST_DIR}"
        echo -e "${GREEN}✅ Test files cleaned up${NC}"
    fi
}

# Set trap for cleanup
trap cleanup EXIT

# Run main function
main "$@"
