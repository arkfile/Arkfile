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
    echo "Arkfile Go Module Update Helper"
    echo
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "Options:"
    echo "  --all         Update all modules (with confirmations)"
    echo "  --patch       Update patch versions only (1.0.1 → 1.0.2)"
    echo "  --minor       Update minor versions only (1.0.x → 1.1.0)"
    echo "  --major       Update major versions only (1.x.x → 2.0.0)"
    echo "  --test-only   Run tests without updating"
    echo "  --help        Show this help"
    echo
    echo "Examples:"
    echo "  $0              # Interactive mode"
    echo "  $0 --patch     # Update only patch versions"
    echo "  $0 --all       # Update all with confirmations"
}

# Parse command line arguments
UPDATE_MODE="interactive"
RUN_TESTS=true

while [[ $# -gt 0 ]]; do
    case $1 in
        --all)
            UPDATE_MODE="all"
            shift
            ;;
        --patch)
            UPDATE_MODE="patch"
            shift
            ;;
        --minor)
            UPDATE_MODE="minor"
            shift
            ;;
        --major)
            UPDATE_MODE="major"
            shift
            ;;
        --test-only)
            UPDATE_MODE="test-only"
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

# Check if we're in the right directory
check_environment() {
    if [[ ! -f "$PROJECT_ROOT/go.mod" ]]; then
        echo -e "${RED}❌ go.mod not found in $PROJECT_ROOT${NC}"
        echo "Please run this script from the arkfile project root or scripts directory."
        exit 1
    fi
    
    cd "$PROJECT_ROOT"
    
    if ! command -v go &> /dev/null; then
        echo -e "${RED}❌ Go is not installed or not in PATH${NC}"
        exit 1
    fi
}

# Categorize update by semantic version
get_update_type() {
    local current="$1"
    local latest="$2"
    
    # Remove 'v' prefix if present
    current=$(echo "$current" | sed 's/^v//')
    latest=$(echo "$latest" | sed 's/^v//')
    
    # Extract version parts
    local current_major=$(echo "$current" | cut -d. -f1)
    local current_minor=$(echo "$current" | cut -d. -f2)
    local current_patch=$(echo "$current" | cut -d. -f3 | cut -d- -f1)
    
    local latest_major=$(echo "$latest" | cut -d. -f1)
    local latest_minor=$(echo "$latest" | cut -d. -f2)
    local latest_patch=$(echo "$latest" | cut -d. -f3 | cut -d- -f1)
    
    # Compare versions
    if [[ "$current_major" != "$latest_major" ]]; then
        echo "major"
    elif [[ "$current_minor" != "$latest_minor" ]]; then
        echo "minor"
    elif [[ "$current_patch" != "$latest_patch" ]]; then
        echo "patch"
    else
        echo "same"
    fi
}

# Get available updates
get_updates() {
    local update_type="$1"
    local -a updates=()
    
    while IFS=' ' read -r module current latest indirect; do
        # Remove brackets from latest version (go list output format)
        latest=$(echo "$latest" | sed 's/\[//g' | sed 's/\]//g')
        
        if [[ "$current" != "$latest" && -n "$latest" && "$latest" != "$current" ]]; then
            local type=$(get_update_type "$current" "$latest")
            
            if [[ "$update_type" == "all" || "$update_type" == "$type" ]]; then
                updates+=("$module:$current:$latest:$type")
            fi
        fi
    done < <(go list -u -m all 2>/dev/null | grep -v "^$(go list -m)$")
    
    printf '%s\n' "${updates[@]}"
}

# Run tests
run_tests() {
    echo -e "${BLUE}🧪 Running tests...${NC}"
    
    if go test ./... -timeout=30s; then
        echo -e "${GREEN}✅ All tests passed${NC}"
        return 0
    else
        echo -e "${RED}❌ Tests failed${NC}"
        return 1
    fi
}

# Update a single module
update_module() {
    local module="$1"
    local latest="$2"
    
    echo -e "${BLUE}📦 Updating $module to $latest...${NC}"
    
    if go get "$module@$latest"; then
        echo -e "${GREEN}✅ Updated $module${NC}"
        return 0
    else
        echo -e "${RED}❌ Failed to update $module${NC}"
        return 1
    fi
}

# Interactive mode
interactive_mode() {
    local -a patch_updates=()
    local -a minor_updates=()
    local -a major_updates=()
    
    # Categorize all updates
    while IFS=':' read -r module current latest type; do
        case "$type" in
            "patch") patch_updates+=("$module:$current:$latest:$type") ;;
            "minor") minor_updates+=("$module:$current:$latest:$type") ;;
            "major") major_updates+=("$module:$current:$latest:$type") ;;
        esac
    done < <(get_updates "all")
    
    if [[ ${#patch_updates[@]} -eq 0 && ${#minor_updates[@]} -eq 0 && ${#major_updates[@]} -eq 0 ]]; then
        echo -e "${GREEN}✅ All Go modules are up to date!${NC}"
        return 0
    fi
    
    echo -e "${CYAN}🔧 Go Module Updates Available:${NC}"
    echo
    
    # Show patch updates
    if [[ ${#patch_updates[@]} -gt 0 ]]; then
        echo -e "${GREEN}Patch Updates (likely safe):${NC}"
        for i in "${!patch_updates[@]}"; do
            IFS=':' read -r module current latest type <<< "${patch_updates[$i]}"
            printf "  [%d] %-35s %s → %s\n" $((i+1)) "$module:" "$current" "$latest"
        done
        echo
    fi
    
    # Show minor updates
    if [[ ${#minor_updates[@]} -gt 0 ]]; then
        echo -e "${YELLOW}Minor Updates (test recommended):${NC}"
        local start_idx=$((${#patch_updates[@]} + 1))
        for i in "${!minor_updates[@]}"; do
            IFS=':' read -r module current latest type <<< "${minor_updates[$i]}"
            printf "  [%d] %-35s %s → %s\n" $((start_idx + i)) "$module:" "$current" "$latest"
        done
        echo
    fi
    
    # Show major updates
    if [[ ${#major_updates[@]} -gt 0 ]]; then
        echo -e "${RED}Major Updates (review recommended):${NC}"
        local start_idx=$((${#patch_updates[@]} + ${#minor_updates[@]} + 1))
        for i in "${!major_updates[@]}"; do
            IFS=':' read -r module current latest type <<< "${major_updates[$i]}"
            printf "  [%d] %-35s %s → %s\n" $((start_idx + i)) "$module:" "$current" "$latest"
        done
        echo
    fi
    
    echo "Select updates to apply:"
    echo "  [a] All patch updates"
    echo "  [b] All minor updates" 
    echo "  [c] All updates"
    echo "  [t] Run tests only"
    echo "  [q] Quit"
    echo
    read -p "Choice: " -r choice
    
    case "$choice" in
        a|A)
            if [[ ${#patch_updates[@]} -gt 0 ]]; then
                apply_updates patch
            else
                echo "No patch updates available."
            fi
            ;;
        b|B)
            if [[ ${#minor_updates[@]} -gt 0 ]]; then
                apply_updates minor
            else
                echo "No minor updates available."
            fi
            ;;
        c|C)
            apply_updates all
            ;;
        t|T)
            run_tests
            ;;
        q|Q)
            echo "Exiting..."
            exit 0
            ;;
        *)
            echo "Invalid choice. Exiting..."
            exit 1
            ;;
    esac
}

# Apply updates based on type
apply_updates() {
    local update_type="$1"
    local updates
    local success=true
    
    echo -e "${BLUE}📦 Applying $update_type updates...${NC}"
    echo
    
    mapfile -t updates < <(get_updates "$update_type")
    
    if [[ ${#updates[@]} -eq 0 ]]; then
        echo -e "${GREEN}✅ No $update_type updates available${NC}"
        return 0
    fi
    
    # Apply updates
    for update in "${updates[@]}"; do
        IFS=':' read -r module current latest type <<< "$update"
        
        if ! update_module "$module" "$latest"; then
            success=false
            break
        fi
    done
    
    if [[ "$success" == "true" ]]; then
        echo
        echo -e "${BLUE}📝 Cleaning up dependencies...${NC}"
        if go mod tidy; then
            echo -e "${GREEN}✅ Dependencies cleaned up${NC}"
        else
            echo -e "${YELLOW}⚠️  Warning: go mod tidy failed${NC}"
        fi
        
        echo
        if run_tests; then
            echo
            echo -e "${GREEN}Updates completed successfully!${NC}"
            
            # Show summary
            echo
            echo -e "${CYAN}📋 Updated modules:${NC}"
            for update in "${updates[@]}"; do
                IFS=':' read -r module current latest type <<< "$update"
                printf "  %-35s %s → %s\n" "$module:" "$current" "$latest"
            done
        else
            echo
            echo -e "${RED}❌ Updates applied but tests failed${NC}"
            echo -e "${YELLOW}💡 Consider reverting changes with: git checkout go.mod go.sum${NC}"
            exit 1
        fi
    else
        echo
        echo -e "${RED}❌ Update process failed${NC}"
        echo -e "${YELLOW}💡 Consider reverting changes with: git checkout go.mod go.sum${NC}"
        exit 1
    fi
}

# Main execution
main() {
    check_environment
    
    echo -e "${BLUE}🔍 Arkfile Go Module Updater${NC}"
    echo
    
    if [[ "$UPDATE_MODE" == "test-only" ]]; then
        run_tests
        exit $?
    fi
    
    if [[ "$UPDATE_MODE" == "interactive" ]]; then
        interactive_mode
    else
        apply_updates "$UPDATE_MODE"
    fi
}

# Run main function
main "$@"
