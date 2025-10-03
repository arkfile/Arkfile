#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Help function
show_help() {
    echo "Arkfile Unified Dependency Updater"
    echo
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "Options:"
    echo "  --check      Check for updates only (no menu)"
    echo "  --help       Show this help"
    echo
    echo "Examples:"
    echo "  $0           # Interactive menu"
    echo "  $0 --check  # Just check for updates"
}

# Parse command line arguments
CHECK_ONLY=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --check)
            CHECK_ONLY=true
            shift
            ;;
        --help)
            show_help
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Check if required scripts exist
check_scripts() {
    local missing_scripts=()
    
    if [[ ! -f "$SCRIPT_DIR/check-updates.sh" ]]; then
        missing_scripts+=("check-updates.sh")
    fi
    
    if [[ ! -f "$SCRIPT_DIR/update-go-deps.sh" ]]; then
        missing_scripts+=("update-go-deps.sh")
    fi
    
    if [[ ! -f "$SCRIPT_DIR/setup-rqlite.sh" ]]; then
        missing_scripts+=("setup-rqlite.sh")
    fi
    
    if [[ ! -f "$SCRIPT_DIR/setup-minio.sh" ]]; then
        missing_scripts+=("setup-minio.sh")
    fi
    
    if [[ ${#missing_scripts[@]} -gt 0 ]]; then
        echo -e "${RED}[X] Missing required scripts: ${missing_scripts[*]}${NC}"
        echo "Please ensure all dependency management scripts are present."
        exit 1
    fi
}

# Check for updates and parse results
check_for_updates() {
    local check_output
    local rqlite_updates=false
    local minio_updates=false
    local go_updates=false
    
    echo -e "${BLUE}🔍 Checking for available updates...${NC}"
    echo
    
    # Run the check-updates script and capture output
    if check_output=$("$SCRIPT_DIR/check-updates.sh" 2>/dev/null); then
        echo "$check_output"
        
        # Parse output to determine what updates are available
        if echo "$check_output" | grep -q "^  rqlite:.*⬆️"; then
            rqlite_updates=true
        fi
        
        if echo "$check_output" | grep -q "^  MinIO:.*⬆️"; then
            minio_updates=true
        fi
        
        if echo "$check_output" | grep -q "Go Module Updates:" || echo "$check_output" | grep -q "⬆️.*patch)"; then
            go_updates=true
        fi
        
        # Set global variables for menu
        export RQLITE_UPDATES=$rqlite_updates
        export MINIO_UPDATES=$minio_updates
        export GO_UPDATES=$go_updates
        
        # Return true if any updates available
        if [[ "$rqlite_updates" == "true" || "$minio_updates" == "true" || "$go_updates" == "true" ]]; then
            return 0
        else
            return 1
        fi
    else
        echo -e "${RED}[X] Failed to check for updates${NC}"
        return 1
    fi
}

# Show interactive menu
show_menu() {
    echo
    echo -e "${CYAN}[INFO] Available Actions:${NC}"
    
    option=1
    
    # Clear all option variables first
    unset RQLITE_OPTION MINIO_OPTION GO_OPTION ALL_SYSTEM_OPTION ALL_OPTION RECHECK_OPTION TEST_OPTION
    
    # System dependency options
    if [[ "$RQLITE_UPDATES" == "true" ]]; then
        echo -e "  [$option] Update rqlite"
        export RQLITE_OPTION=$option
        option=$((option + 1))
    fi
    
    if [[ "$MINIO_UPDATES" == "true" ]]; then
        echo -e "  [$option] Update MinIO"
        export MINIO_OPTION=$option
        option=$((option + 1))
    fi
    
    # Go modules option
    if [[ "$GO_UPDATES" == "true" ]]; then
        echo -e "  [$option] Update Go modules (interactive)"
        export GO_OPTION=$option
        option=$((option + 1))
    fi
    
    # Combined options if multiple updates available
    update_count=0
    if [[ "$RQLITE_UPDATES" == "true" ]]; then update_count=$((update_count + 1)); fi
    if [[ "$MINIO_UPDATES" == "true" ]]; then update_count=$((update_count + 1)); fi
    if [[ "$GO_UPDATES" == "true" ]]; then update_count=$((update_count + 1)); fi
    
    if [[ $update_count -gt 1 ]]; then
        echo -e "  [$option] Update all system dependencies"
        export ALL_SYSTEM_OPTION=$option
        option=$((option + 1))
        
        echo -e "  [$option] Update everything"
        export ALL_OPTION=$option
        option=$((option + 1))
    fi
    
    # Always available options
    echo -e "  [$option] Re-check for updates"
    export RECHECK_OPTION=$option
    option=$((option + 1))
    
    echo -e "  [$option] Run tests only"
    export TEST_OPTION=$option
    option=$((option + 1))
    
    echo -e "  [q] Quit"
    echo
    read -p "Choice: " -r choice
    echo
    handle_choice "$choice"
}

# Execute user choice
handle_choice() {
    local choice="$1"
    
    case "$choice" in
        q|Q)
            echo "Exiting..."
            exit 0
            ;;
        "$RQLITE_OPTION")
            if [[ -n "$RQLITE_OPTION" ]]; then
                echo -e "${BLUE}🔧 Updating rqlite...${NC}"
                if "$SCRIPT_DIR/setup-rqlite.sh"; then
                    echo -e "${GREEN}[OK] rqlite updated successfully${NC}"
                else
                    echo -e "${RED}[X] rqlite update failed${NC}"
                fi
            else
                echo "Invalid choice"
            fi
            ;;
        "$MINIO_OPTION")
            if [[ -n "$MINIO_OPTION" ]]; then
                echo -e "${BLUE}🔧 Updating MinIO...${NC}"
                if "$SCRIPT_DIR/setup-minio.sh"; then
                    echo -e "${GREEN}[OK] MinIO updated successfully${NC}"
                else
                    echo -e "${RED}[X] MinIO update failed${NC}"
                fi
            else
                echo "Invalid choice"
            fi
            ;;
        "$GO_OPTION")
            if [[ -n "$GO_OPTION" ]]; then
                echo -e "${BLUE}🔧 Starting Go module updater...${NC}"
                "$SCRIPT_DIR/update-go-deps.sh"
            else
                echo "Invalid choice"
            fi
            ;;
        "$ALL_SYSTEM_OPTION")
            if [[ -n "$ALL_SYSTEM_OPTION" ]]; then
                echo -e "${BLUE}🔧 Updating all system dependencies...${NC}"
                local success=true
                
                if [[ "$RQLITE_UPDATES" == "true" ]]; then
                    echo -e "${CYAN}Updating rqlite...${NC}"
                    if ! "$SCRIPT_DIR/setup-rqlite.sh"; then
                        success=false
                    fi
                fi
                
                if [[ "$MINIO_UPDATES" == "true" ]]; then
                    echo -e "${CYAN}Updating MinIO...${NC}"
                    if ! "$SCRIPT_DIR/setup-minio.sh"; then
                        success=false
                    fi
                fi
                
                if [[ "$success" == "true" ]]; then
                    echo -e "${GREEN}[OK] All system dependencies updated successfully${NC}"
                else
                    echo -e "${RED}[X] Some system dependency updates failed${NC}"
                fi
            else
                echo "Invalid choice"
            fi
            ;;
        "$ALL_OPTION")
            if [[ -n "$ALL_OPTION" ]]; then
                echo -e "${BLUE}🔧 Updating all dependencies...${NC}"
                
                # Update system dependencies first
                if [[ "$RQLITE_UPDATES" == "true" || "$MINIO_UPDATES" == "true" ]]; then
                    handle_choice "$ALL_SYSTEM_OPTION"
                fi
                
                # Then update Go modules
                if [[ "$GO_UPDATES" == "true" ]]; then
                    echo
                    echo -e "${CYAN}Starting Go module updates...${NC}"
                    "$SCRIPT_DIR/update-go-deps.sh"
                fi
            else
                echo "Invalid choice"
            fi
            ;;
        "$RECHECK_OPTION")
            if [[ -n "$RECHECK_OPTION" ]]; then
                echo -e "${BLUE}🔄 Rechecking for updates...${NC}"
                main
                return
            else
                echo "Invalid choice"
            fi
            ;;
        "$TEST_OPTION")
            if [[ -n "$TEST_OPTION" ]]; then
                echo -e "${BLUE}🧪 Running tests...${NC}"
                cd "$PROJECT_ROOT"
                if go test ./...; then
                    echo -e "${GREEN}[OK] All tests passed${NC}"
                else
                    echo -e "${RED}[X] Some tests failed${NC}"
                fi
            else
                echo "Invalid choice"
            fi
            ;;
        *)
            echo "Invalid choice: $choice"
            ;;
    esac
}

# Interactive mode
interactive_mode() {
    while true; do
        show_menu
        
        # Ask if user wants to continue
        echo
        read -p "Continue? (y/n): " -r continue_choice
        case "$continue_choice" in
            y|Y|yes|YES)
                echo
                # Re-check for updates
                if ! check_for_updates; then
                    echo
                    echo -e "${GREEN}[OK] All dependencies are now up to date!${NC}"
                    break
                fi
                ;;
            *)
                echo "Exiting..."
                break
                ;;
        esac
    done
}

# Main execution
main() {
    check_scripts
    
    echo -e "${BLUE}[START] Arkfile Dependency Manager${NC}"
    echo
    
    if check_for_updates; then
        if [[ "$CHECK_ONLY" == "true" ]]; then
            echo
            echo -e "${YELLOW}💡 Run without --check to use interactive updater${NC}"
        else
            interactive_mode
        fi
    else
        echo
        echo -e "${GREEN}[OK] All dependencies are up to date!${NC}"
    fi
}

# Run main function
main "$@"
