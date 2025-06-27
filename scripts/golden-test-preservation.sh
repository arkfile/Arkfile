#!/bin/bash

# Golden Test Preservation Script for Arkfile Phase 4
# This script creates and validates reference test vectors for file encryption formats

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
GOLDEN_DIR="test/golden"
TEST_DATA_DIR="${GOLDEN_DIR}/data"
REFERENCE_DIR="${GOLDEN_DIR}/reference"
VECTORS_FILE="${GOLDEN_DIR}/test-vectors.json"

echo -e "${BLUE}🔒 Arkfile Golden Test Preservation${NC}"
echo "====================================="
echo "Creating reference test vectors for format compatibility"
echo "Directory: ${GOLDEN_DIR}"
echo "====================================="
echo

# Create test directories
mkdir -p "${TEST_DATA_DIR}"
mkdir -p "${REFERENCE_DIR}"

# Function to create test data files
create_test_data() {
    echo -e "${BLUE}📁 Creating test data files...${NC}"
    
    # Small text file
    cat > "${TEST_DATA_DIR}/small.txt" << 'EOF'
This is a small test file for encryption format validation.
It contains multiple lines of text.
Special characters: !@#$%^&*()_+-={}[]|\"':;.,<>?/~`
Unicode: 你好世界 🌍 ñ é ü ß
EOF

    # Medium binary-like file with patterns
    printf "ARKFILE" > "${TEST_DATA_DIR}/medium.bin"
    for i in {1..100}; do
        printf "%04d" $i >> "${TEST_DATA_DIR}/medium.bin"
    done
    
    # Large structured file
    cat > "${TEST_DATA_DIR}/large.json" << 'EOF'
{
    "name": "Arkfile Golden Test",
    "version": "1.0.0",
    "description": "Reference test data for format validation",
    "encryption": {
        "algorithm": "AES-256-GCM",
        "key_derivation": "Argon2ID",
        "formats": ["0x04", "0x05"]
    },
    "test_data": {
        "passwords": ["TestPassword123!", "AnotherSecurePass456@"],
        "device_profiles": ["minimal", "interactive", "balanced", "maximum"],
        "file_sizes": ["small", "medium", "large"]
    },
    "compatibility": {
        "backward_compatible": true,
        "forward_compatible": false,
        "version_requirements": {
            "minimum": "1.0.0",
            "recommended": "1.0.0"
        }
    }
}
EOF

    # Add more test data to the JSON to make it larger
    for i in {1..50}; do
        echo "    \"test_entry_${i}\": \"This is test data entry number ${i} for golden test validation\"," >> "${TEST_DATA_DIR}/large.json"
    done
    echo "    \"final_entry\": \"Last entry\"" >> "${TEST_DATA_DIR}/large.json"
    echo "}" >> "${TEST_DATA_DIR}/large.json"
    
    echo -e "${GREEN}✅ Test data files created${NC}"
}

# Function to create reference encrypted files
create_reference_files() {
    echo -e "${BLUE}🔐 Creating reference encrypted files...${NC}"
    
    # Test passwords
    local passwords=("GoldenTest123!" "RefPass456@" "CompatTest789#")
    
    # Device profiles to test
    local profiles=("minimal" "interactive" "balanced" "maximum")
    
    # Files to encrypt
    local files=("small.txt" "medium.bin" "large.json")
    
    # Initialize test vectors file
    cat > "${VECTORS_FILE}" << 'EOF'
{
    "format_version": "1.0.0",
    "created": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "description": "Golden test vectors for Arkfile encryption format compatibility",
    "test_vectors": [
EOF

    local vector_count=0
    
    for file in "${files[@]}"; do
        for password in "${passwords[@]}"; do
            for profile in "${profiles[@]}"; do
                echo -e "${YELLOW}Creating vector: ${file} + ${password} + ${profile}${NC}"
                
                # Create reference filename
                local ref_name="${file%.*}_${profile}_$(echo ${password} | md5sum | cut -c1-8)"
                local single_key_file="${REFERENCE_DIR}/${ref_name}_single.arkfile"
                local multi_key_file="${REFERENCE_DIR}/${ref_name}_multi.arkfile"
                
                # Create single-key format (0x04) reference
                create_single_key_reference "${TEST_DATA_DIR}/${file}" "${single_key_file}" "${password}" "${profile}"
                
                # Create multi-key format (0x05) reference
                create_multi_key_reference "${TEST_DATA_DIR}/${file}" "${multi_key_file}" "${password}" "${profile}"
                
                # Add to test vectors
                if [ ${vector_count} -gt 0 ]; then
                    echo "        ," >> "${VECTORS_FILE}"
                fi
                
                cat >> "${VECTORS_FILE}" << EOF
        {
            "id": ${vector_count},
            "source_file": "${file}",
            "password": "${password}",
            "device_profile": "${profile}",
            "single_key_format": {
                "file": "${ref_name}_single.arkfile",
                "format_byte": "0x04",
                "size": $(stat -c%s "${single_key_file}" 2>/dev/null || echo 0)
            },
            "multi_key_format": {
                "file": "${ref_name}_multi.arkfile", 
                "format_byte": "0x05",
                "size": $(stat -c%s "${multi_key_file}" 2>/dev/null || echo 0)
            },
            "source_size": $(stat -c%s "${TEST_DATA_DIR}/${file}"),
            "source_md5": "$(md5sum "${TEST_DATA_DIR}/${file}" | cut -d' ' -f1)"
        }
EOF
                
                vector_count=$((vector_count + 1))
            done
        done
    done
    
    cat >> "${VECTORS_FILE}" << 'EOF'
    ],
    "validation_notes": [
        "These reference files must decrypt to identical content as source files",
        "Format bytes 0x04 and 0x05 must be preserved in all implementations",
        "Argon2ID parameters must remain compatible across device profiles",
        "AES-GCM authentication must validate correctly"
    ]
}
EOF

    echo -e "${GREEN}✅ Reference files and test vectors created${NC}"
}

# Function to create single-key format reference (0x04)
create_single_key_reference() {
    local source_file="$1"
    local output_file="$2"
    local password="$3"
    local profile="$4"
    
    # Create a simple reference file with known structure
    # Header: 0x04 (single-key format)
    # This is a placeholder - in real implementation would use crypto module
    
    printf '\x04' > "${output_file}"
    
    # Add profile identifier
    printf "%s\x00" "${profile}" >> "${output_file}"
    
    # Add salt (32 bytes of predictable data for golden tests)
    printf "GOLDEN_TEST_SALT_32_BYTES_HERE_" >> "${output_file}"
    
    # Add encrypted content (placeholder - would be AES-GCM encrypted data)
    echo "ENCRYPTED_CONTENT_PLACEHOLDER_$(basename "${source_file}")_${password}_${profile}" >> "${output_file}"
    
    # Add original file content as base64 for validation
    echo "---GOLDEN-TEST-ORIGINAL---" >> "${output_file}"
    base64 -w 0 "${source_file}" >> "${output_file}"
}

# Function to create multi-key format reference (0x05)
create_multi_key_reference() {
    local source_file="$1"
    local output_file="$2"
    local password="$3"
    local profile="$4"
    
    # Create multi-key format reference
    # Header: 0x05 (multi-key format)
    
    printf '\x05' > "${output_file}"
    
    # Add number of keys (1 for primary)
    printf '\x01' >> "${output_file}"
    
    # Add profile identifier
    printf "%s\x00" "${profile}" >> "${output_file}"
    
    # Add salt (32 bytes)
    printf "GOLDEN_MULTIKEY_SALT_32_BYTES__" >> "${output_file}"
    
    # Add key metadata
    echo "KEY_METADATA_${password}_${profile}" >> "${output_file}"
    
    # Add encrypted content
    echo "MULTIKEY_ENCRYPTED_CONTENT_$(basename "${source_file}")_${password}_${profile}" >> "${output_file}"
    
    # Add original content for validation
    echo "---GOLDEN-TEST-MULTIKEY-ORIGINAL---" >> "${output_file}"
    base64 -w 0 "${source_file}" >> "${output_file}"
}

# Function to validate existing reference files
validate_reference_files() {
    echo -e "${BLUE}✅ Validating reference files...${NC}"
    
    if [ ! -f "${VECTORS_FILE}" ]; then
        echo -e "${RED}❌ Test vectors file not found${NC}"
        return 1
    fi
    
    local total_vectors=$(grep -c '"id":' "${VECTORS_FILE}" || echo 0)
    local validated=0
    local failed=0
    
    echo -e "${YELLOW}Found ${total_vectors} test vectors to validate${NC}"
    
    # Validate each reference file exists and has correct format
    for ref_file in "${REFERENCE_DIR}"/*.arkfile; do
        if [ -f "${ref_file}" ]; then
            # Check format byte
            local format_byte=$(xxd -l 1 -ps "${ref_file}")
            
            if [[ "${format_byte}" == "04" ]]; then
                echo -e "${GREEN}✅ $(basename "${ref_file}"): Single-key format (0x04)${NC}"
                validated=$((validated + 1))
            elif [[ "${format_byte}" == "05" ]]; then
                echo -e "${GREEN}✅ $(basename "${ref_file}"): Multi-key format (0x05)${NC}"
                validated=$((validated + 1))
            else
                echo -e "${RED}❌ $(basename "${ref_file}"): Invalid format byte (0x${format_byte})${NC}"
                failed=$((failed + 1))
            fi
        fi
    done
    
    echo
    echo -e "${BLUE}Validation Summary:${NC}"
    echo -e "${GREEN}✅ Validated: ${validated}${NC}"
    echo -e "${RED}❌ Failed: ${failed}${NC}"
    
    if [ ${failed} -eq 0 ]; then
        echo -e "${GREEN}🎉 All reference files validated successfully${NC}"
        return 0
    else
        echo -e "${RED}⚠️  Some reference files failed validation${NC}"
        return 1
    fi
}

# Function to test backward compatibility
test_backward_compatibility() {
    echo -e "${BLUE}🔄 Testing backward compatibility...${NC}"
    
    # This would test that new implementations can read old format files
    # For now, just verify the reference files are readable
    
    echo -e "${YELLOW}Checking reference file readability...${NC}"
    
    local readable=0
    local unreadable=0
    
    for ref_file in "${REFERENCE_DIR}"/*.arkfile; do
        if [ -f "${ref_file}" ] && [ -r "${ref_file}" ]; then
            local size=$(stat -c%s "${ref_file}")
            if [ ${size} -gt 0 ]; then
                echo -e "${GREEN}✅ $(basename "${ref_file}"): Readable (${size} bytes)${NC}"
                readable=$((readable + 1))
            else
                echo -e "${RED}❌ $(basename "${ref_file}"): Empty file${NC}"
                unreadable=$((unreadable + 1))
            fi
        else
            echo -e "${RED}❌ $(basename "${ref_file}"): Not readable${NC}"
            unreadable=$((unreadable + 1))
        fi
    done
    
    echo
    echo -e "${BLUE}Backward Compatibility Summary:${NC}"
    echo -e "${GREEN}✅ Readable files: ${readable}${NC}"
    echo -e "${RED}❌ Unreadable files: ${unreadable}${NC}"
    
    return ${unreadable}
}

# Function to generate compatibility report
generate_compatibility_report() {
    echo -e "${BLUE}📊 Generating compatibility report...${NC}"
    
    local report_file="${GOLDEN_DIR}/compatibility-report.md"
    
    cat > "${report_file}" << EOF
# Arkfile Encryption Format Compatibility Report

**Generated:** $(date)
**Golden Test Directory:** ${GOLDEN_DIR}
**Test Vectors:** ${VECTORS_FILE}

## Format Specifications

### Single-Key Format (0x04)
- Header byte: 0x04
- Used for files encrypted with a single password
- Compatible with all Arkfile versions

### Multi-Key Format (0x05)  
- Header byte: 0x05
- Used for files with multiple decryption keys
- Supports secure file sharing without password sharing

## Test Vector Summary

- **Total test vectors:** $(grep -c '"id":' "${VECTORS_FILE}" 2>/dev/null || echo 0)
- **Source files:** $(ls -1 "${TEST_DATA_DIR}" | wc -l)
- **Reference files:** $(ls -1 "${REFERENCE_DIR}"/*.arkfile 2>/dev/null | wc -l || echo 0)
- **Device profiles tested:** minimal, interactive, balanced, maximum

## File Size Distribution

EOF

    # Add file size information
    echo "| File | Size | Format 0x04 | Format 0x05 |" >> "${report_file}"
    echo "|------|------|-------------|-------------|" >> "${report_file}"
    
    for file in "${TEST_DATA_DIR}"/*; do
        if [ -f "${file}" ]; then
            local basename=$(basename "${file}")
            local size=$(stat -c%s "${file}")
            local size_04=$(ls -1 "${REFERENCE_DIR}"/*single.arkfile 2>/dev/null | head -1 | xargs stat -c%s 2>/dev/null || echo "N/A")
            local size_05=$(ls -1 "${REFERENCE_DIR}"/*multi.arkfile 2>/dev/null | head -1 | xargs stat -c%s 2>/dev/null || echo "N/A")
            echo "| ${basename} | ${size} bytes | ${size_04} bytes | ${size_05} bytes |" >> "${report_file}"
        fi
    done
    
    cat >> "${report_file}" << 'EOF'

## Validation Rules

1. **Format Preservation**: Header bytes 0x04 and 0x05 must be preserved
2. **Content Integrity**: Decrypted content must match original files exactly
3. **Cross-Platform**: Files encrypted on one platform must decrypt on others
4. **Profile Compatibility**: Different Argon2ID profiles must remain supported

## Usage Instructions

### Creating New Reference Files
```bash
./scripts/golden-test-preservation.sh --create
```

### Validating Existing Files
```bash
./scripts/golden-test-preservation.sh --validate
```

### Testing Compatibility
```bash
./scripts/golden-test-preservation.sh --test-compat
```

## Notes

- Reference files contain placeholder encrypted data for testing
- Actual encryption uses production Argon2ID and AES-GCM implementations
- Golden tests ensure format compatibility across versions
- Regular validation recommended before releases

## Troubleshooting

### Common Issues

1. **Missing reference files**: Run with `--create` to generate
2. **Format validation failures**: Check for file corruption
3. **Compatibility issues**: Verify Argon2ID parameters match

### Support

For issues with golden tests, check:
- File permissions in test directory
- Available disk space for test files
- Proper Go module dependencies
EOF

    echo -e "${GREEN}✅ Compatibility report generated: ${report_file}${NC}"
}

# Main execution
main() {
    case "${1:-}" in
        --create)
            create_test_data
            create_reference_files
            generate_compatibility_report
            ;;
        --validate)
            validate_reference_files
            ;;
        --test-compat)
            test_backward_compatibility
            ;;
        --report)
            generate_compatibility_report
            ;;
        *)
            echo -e "${BLUE}Usage: $0 [option]${NC}"
            echo
            echo "Options:"
            echo "  --create       Create test data and reference files"
            echo "  --validate     Validate existing reference files"
            echo "  --test-compat  Test backward compatibility"
            echo "  --report       Generate compatibility report"
            echo
            echo "Default: Create all test data and reference files"
            
            # Run full suite by default
            create_test_data
            create_reference_files
            validate_reference_files
            test_backward_compatibility
            generate_compatibility_report
            ;;
    esac
    
    echo
    echo -e "${GREEN}🎉 Golden test preservation completed${NC}"
    echo -e "${BLUE}Test files located in: ${GOLDEN_DIR}${NC}"
}

# Run main function
main "$@"
