#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
DRY_RUN=false
CREATE_BACKUP=true
VERBOSE=false

# File extensions to target
TARGET_EXTENSIONS=("go" "sh" "ts" "js" "md")

# Directories to exclude
EXCLUDE_DIRS=("vendor" "node_modules" ".git" "build" "dist" "target" ".cache")

# Comprehensive emoji Unicode ranges
EMOJI_PATTERNS=(
    # Emoticons
    $'[\U1F600-\U1F64F]'
    # Miscellaneous Symbols and Pictographs
    $'[\U1F300-\U1F5FF]'
    # Transport and Map Symbols
    $'[\U1F680-\U1F6FF]'
    # Supplemental Symbols and Pictographs
    $'[\U1F900-\U1F9FF]'
    # Symbols and Pictographs Extended-A
    $'[\U1FA70-\U1FAFF]'
    # Miscellaneous Symbols
    $'[\U2600-\U26FF]'
    # Dingbats
    $'[\U2700-\U27BF]'
    # Enclosed Alphanumeric Supplement
    $'[\U1F100-\U1F1FF]'
    # Geometric Shapes Extended
    $'[\U1F780-\U1F7FF]'
    # Supplemental Arrows-C
    $'[\U1F800-\U1F8FF]'
    # Chess Symbols
    $'[\U1FA00-\U1FA6F]'
    # Additional common emojis
    $'[\U2194-\U2199]'
    $'[\U21A9-\U21AA]'
    $'[\U231A-\U231B]'
    $'[\U2328]'
    $'[\U23CF]'
    $'[\U23E9-\U23F3]'
    $'[\U23F8-\U23FA]'
    $'[\U24C2]'
    $'[\U25AA-\U25AB]'
    $'[\U25B6]'
    $'[\U25C0]'
    $'[\U25FB-\U25FE]'
    $'[\U2B05-\U2B07]'
    $'[\U2B1B-\U2B1C]'
    $'[\U2B50]'
    $'[\U2B55]'
    $'[\U3030]'
    $'[\U303D]'
    $'[\U3297]'
    $'[\U3299]'
)

usage() {
    echo "Emoji Removal Script for Arkfile Codebase"
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  --dry-run          Show what would be changed without making changes"
    echo "  --no-backup        Don't create backup files (.bak)"
    echo "  --verbose          Show detailed output"
    echo "  --help             Show this help"
    echo ""
    echo "Target file types: ${TARGET_EXTENSIONS[*]}"
    echo "Excluded directories: ${EXCLUDE_DIRS[*]}"
    echo ""
    echo "This script removes all Unicode emoji characters from source code files."
    echo "By default, it creates .bak backup files before making changes."
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --no-backup)
            CREATE_BACKUP=false
            shift
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        --help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Build find command with exclusions
build_find_command() {
    local cmd="find . -type f"
    
    # Add exclusions for directories
    for dir in "${EXCLUDE_DIRS[@]}"; do
        cmd="$cmd -not -path \"./$dir/*\""
    done
    
    # Add file extension filters
    cmd="$cmd \\("
    for i in "${!TARGET_EXTENSIONS[@]}"; do
        if [ $i -gt 0 ]; then
            cmd="$cmd -o"
        fi
        cmd="$cmd -name \"*.${TARGET_EXTENSIONS[$i]}\""
    done
    cmd="$cmd \\)"
    
    echo "$cmd"
}

# Check if file contains emojis
contains_emojis() {
    local file="$1"
    for pattern in "${EMOJI_PATTERNS[@]}"; do
        if grep -q "$pattern" "$file" 2>/dev/null; then
            return 0
        fi
    done
    return 1
}

# Remove emojis from file
remove_emojis_from_file() {
    local file="$1"
    local temp_file=$(mktemp)
    local changes_made=false
    
    # Copy original content to temp file
    cp "$file" "$temp_file"
    
    # Apply each emoji pattern removal
    for pattern in "${EMOJI_PATTERNS[@]}"; do
        if sed -i "s/$pattern//g" "$temp_file" 2>/dev/null; then
            # Check if changes were made by comparing file sizes or content
            if ! cmp -s "$file" "$temp_file"; then
                changes_made=true
            fi
        fi
    done
    
    if [ "$changes_made" = true ]; then
        if [ "$DRY_RUN" = true ]; then
            echo "Would modify: $file"
            if [ "$VERBOSE" = true ]; then
                echo "  Changes preview:"
                diff -u "$file" "$temp_file" | head -20 || true
            fi
        else
            # Create backup if requested
            if [ "$CREATE_BACKUP" = true ]; then
                cp "$file" "$file.bak"
                if [ "$VERBOSE" = true ]; then
                    echo "  Created backup: $file.bak"
                fi
            fi
            
            # Apply changes
            mv "$temp_file" "$file"
            echo "Modified: $file"
            
            if [ "$VERBOSE" = true ]; then
                echo "  Emojis removed successfully"
            fi
        fi
        rm -f "$temp_file"
        return 0
    else
        rm -f "$temp_file"
        return 1
    fi
}

# Main execution
main() {
    echo -e "${BLUE}Emoji Removal Script for Arkfile Codebase${NC}"
    echo
    
    if [ "$DRY_RUN" = true ]; then
        echo -e "${YELLOW}DRY RUN MODE - No files will be modified${NC}"
    fi
    
    echo "Target file types: ${TARGET_EXTENSIONS[*]}"
    echo "Excluded directories: ${EXCLUDE_DIRS[*]}"
    echo
    
    # Build and execute find command
    local find_cmd=$(build_find_command)
    echo "Searching for files..."
    if [ "$VERBOSE" = true ]; then
        echo "Find command: $find_cmd"
    fi
    
    # Get list of files
    local files
    files=$(eval "$find_cmd" | sort)
    
    if [ -z "$files" ]; then
        echo -e "${YELLOW}No matching files found${NC}"
        exit 0
    fi
    
    local total_files=0
    local files_with_emojis=0
    local files_modified=0
    
    echo "Processing files..."
    echo
    
    while IFS= read -r file; do
        if [ -z "$file" ]; then
            continue
        fi
        
        total_files=$((total_files + 1))
        
        if [ "$VERBOSE" = true ]; then
            echo "Checking: $file"
        fi
        
        if contains_emojis "$file"; then
            files_with_emojis=$((files_with_emojis + 1))
            
            if remove_emojis_from_file "$file"; then
                files_modified=$((files_modified + 1))
            fi
        elif [ "$VERBOSE" = true ]; then
            echo "  No emojis found"
        fi
    done <<< "$files"
    
    echo
    echo -e "${BLUE}Summary:${NC}"
    echo "Total files scanned: $total_files"
    echo "Files containing emojis: $files_with_emojis"
    
    if [ "$DRY_RUN" = true ]; then
        echo "Files that would be modified: $files_modified"
        echo
        echo -e "${YELLOW}This was a dry run. Use without --dry-run to apply changes.${NC}"
    else
        echo "Files modified: $files_modified"
        
        if [ "$CREATE_BACKUP" = true ] && [ $files_modified -gt 0 ]; then
            echo
            echo -e "${GREEN}Backup files created with .bak extension${NC}"
            echo "To remove backups: find . -name '*.bak' -delete"
        fi
    fi
    
    if [ $files_modified -gt 0 ]; then
        echo
        echo -e "${GREEN}Emoji removal completed successfully!${NC}"
    else
        echo
        echo -e "${GREEN}No emojis found in target files.${NC}"
    fi
}

# Execute main function
main "$@"
