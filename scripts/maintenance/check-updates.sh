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
    echo "Arkfile Dependency Update Checker"
    echo
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "Options:"
    echo "  --rqlite     Check rqlite only"
    echo "  --minio      Check MinIO only"
    echo "  --go         Check Go modules only"
    echo "  --json       Output in JSON format"
    echo "  --help       Show this help"
    echo
    echo "Examples:"
    echo "  $0              # Check all dependencies"
    echo "  $0 --rqlite    # Check rqlite version only"
    echo "  $0 --go --json # Check Go modules with JSON output"
}

# Parse command line arguments
CHECK_RQLITE=true
CHECK_MINIO=true
CHECK_GO=true
JSON_OUTPUT=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --rqlite)
            CHECK_RQLITE=true
            CHECK_MINIO=false
            CHECK_GO=false
            shift
            ;;
        --minio)
            CHECK_RQLITE=false
            CHECK_MINIO=true
            CHECK_GO=false
            shift
            ;;
        --go)
            CHECK_RQLITE=false
            CHECK_MINIO=false
            CHECK_GO=true
            shift
            ;;
        --json)
            JSON_OUTPUT=true
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

# Check if required tools are available
check_tools() {
    local missing_tools=()
    
    if ! command -v curl &> /dev/null; then
        missing_tools+=("curl")
    fi
    
    if ! command -v jq &> /dev/null; then
        missing_tools+=("jq")
    fi
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        echo -e "${RED}[X] Missing required tools: ${missing_tools[*]}${NC}"
        echo "Please install the missing tools and try again."
        exit 1
    fi
}

# Get current rqlite version from setup script
get_current_rqlite_version() {
    local setup_script="${SCRIPT_DIR}/setup-rqlite-build.sh"
    if [[ -f "$setup_script" ]]; then
        grep '^VERSION=' "$setup_script" | head -1 | cut -d'"' -f2 | sed 's/^v*//'
    else
        echo "unknown"
    fi
}

# Get current MinIO version from setup script
get_current_minio_version() {
    local setup_script="${SCRIPT_DIR}/setup-minio.sh"
    if [[ -f "$setup_script" ]]; then
        grep '^MINIO_VERSION=' "$setup_script" | head -1 | cut -d'"' -f2
    else
        echo "unknown"
    fi
}

# Check rqlite version
check_rqlite() {
    local current="v$(get_current_rqlite_version)"
    local latest=""
    local status=""
    
    # Get latest version from GitHub API
    if latest=$(curl -s "https://api.github.com/repos/rqlite/rqlite/releases/latest" | jq -r '.tag_name' 2>/dev/null); then
        if [[ "$latest" == "null" || -z "$latest" ]]; then
            latest="unknown"
            status="error"
        elif [[ "$current" == "$latest" ]]; then
            status="up_to_date"
        else
            status="update_available"
        fi
    else
        latest="unknown"
        status="error"
    fi
    
    if [[ "$JSON_OUTPUT" == "true" ]]; then
        echo "\"rqlite\": {\"current\": \"$current\", \"latest\": \"$latest\", \"status\": \"$status\"},"
    else
        local icon
        case $status in
            "up_to_date") icon="[OK]" ;;
            "update_available") icon="️ " ;;
            "error") icon="[X]" ;;
        esac
        printf "  %-10s %s → %s %s\n" "rqlite:" "$current" "$latest" "$icon"
    fi
}

# Check MinIO version
check_minio() {
    local current="$(get_current_minio_version)"
    local latest=""
    local status=""
    
    # Get latest version from MinIO SHA256 file
    if latest=$(curl -s "https://dl.min.io/server/minio/release/linux-amd64/minio.sha256sum" | grep -o 'RELEASE[^[:space:]]*' | head -1 2>/dev/null); then
        if [[ -z "$latest" ]]; then
            latest="unknown"
            status="error"
        elif [[ "$current" == "$latest" ]]; then
            status="up_to_date"
        else
            status="update_available"
        fi
    else
        latest="unknown"
        status="error"
    fi
    
    if [[ "$JSON_OUTPUT" == "true" ]]; then
        echo "\"minio\": {\"current\": \"$current\", \"latest\": \"$latest\", \"status\": \"$status\"},"
    else
        local icon
        case $status in
            "up_to_date") icon="[OK]" ;;
            "update_available") icon="️ " ;;
            "error") icon="[X]" ;;
        esac
        printf "  %-10s %s → %s %s\n" "MinIO:" "$current" "$latest" "$icon"
    fi
}

# Check Go modules
check_go_modules() {
    if [[ ! -f "$PROJECT_ROOT/go.mod" ]]; then
        if [[ "$JSON_OUTPUT" == "true" ]]; then
            echo "\"go_modules\": {\"error\": \"go.mod not found\"},"
        else
            echo "  Go modules: go.mod not found"
        fi
        return
    fi
    
    cd "$PROJECT_ROOT"
    
    if [[ "$JSON_OUTPUT" == "true" ]]; then
        echo "\"go_modules\": {"
        local first=true
        go list -u -m all 2>/dev/null | grep -v "^$(go list -m)$" | while IFS=' ' read -r module current latest indirect; do
            if [[ "$current" != "$latest" && -n "$latest" && "$latest" != "$current" ]]; then
                if [[ "$first" != "true" ]]; then
                    echo ","
                fi
                echo -n "  \"$module\": {\"current\": \"$current\", \"latest\": \"$latest\"}"
                first=false
            fi
        done
        echo
        echo "},"
    else
        local updates_found=false
        echo
        while IFS=' ' read -r module current latest indirect; do
            if [[ "$current" != "$latest" && -n "$latest" && "$latest" != "$current" ]]; then
                if [[ "$updates_found" == "false" ]]; then
                    echo -e "${CYAN}Go Module Updates:${NC}"
                    updates_found=true
                fi
                
                # Determine update type
                local update_type="patch"
                if [[ "$latest" =~ ^v[0-9]+\. && "$current" =~ ^v[0-9]+\. ]]; then
                    local current_major=$(echo "$current" | cut -d. -f1 | sed 's/v//')
                    local latest_major=$(echo "$latest" | cut -d. -f1 | sed 's/v//')
                    local current_minor=$(echo "$current" | cut -d. -f2)
                    local latest_minor=$(echo "$latest" | cut -d. -f2)
                    
                    if [[ "$current_major" != "$latest_major" ]]; then
                        update_type="major"
                    elif [[ "$current_minor" != "$latest_minor" ]]; then
                        update_type="minor"
                    fi
                fi
                
                printf "  %-35s %s → %s ️  (%s)\n" "$module:" "$current" "$latest" "$update_type"
            fi
        done < <(go list -u -m all 2>/dev/null | grep -v "^$(go list -m)$")
        
        if [[ "$updates_found" == "false" ]]; then
            echo -e "${CYAN}Go Modules:${NC}"
            echo "  All modules up to date [OK]"
        fi
    fi
}

# Main execution
main() {
    check_tools
    
    if [[ "$JSON_OUTPUT" == "true" ]]; then
        echo "{"
        echo "\"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\","
        
        if [[ "$CHECK_RQLITE" == "true" ]]; then
            check_rqlite
        fi
        
        if [[ "$CHECK_MINIO" == "true" ]]; then
            check_minio
        fi
        
        if [[ "$CHECK_GO" == "true" ]]; then
            check_go_modules
        fi
        
        # Remove trailing comma and close JSON
        echo "\"check_complete\": true"
        echo "}"
    else
        echo -e "${BLUE}Checking Arkfile Dependencies...${NC}"
        echo
        
        if [[ "$CHECK_RQLITE" == "true" || "$CHECK_MINIO" == "true" ]]; then
            echo -e "${CYAN}System Dependencies:${NC}"
            
            if [[ "$CHECK_RQLITE" == "true" ]]; then
                check_rqlite
            fi
            
            if [[ "$CHECK_MINIO" == "true" ]]; then
                check_minio
            fi
        fi
        
        if [[ "$CHECK_GO" == "true" ]]; then
            check_go_modules
        fi
        
        # Show update commands if any updates are available
        echo
        echo -e "${YELLOW}To update dependencies:${NC}"
        
        if [[ "$CHECK_RQLITE" == "true" ]]; then
            echo "  ./scripts/setup-rqlite-build.sh     # Update rqlite"
        fi
        
        if [[ "$CHECK_MINIO" == "true" ]]; then
            echo "  ./scripts/setup-minio.sh      # Update MinIO"
        fi
        
        if [[ "$CHECK_GO" == "true" ]]; then
            echo "  ./scripts/update-go-deps.sh   # Update Go modules"
        fi
        
        echo "  ./scripts/update-dependencies.sh # Interactive updater"
    fi
}

# Run main function
main "$@"
