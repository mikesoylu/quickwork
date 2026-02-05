# Shared helpers for run_tests.sh
# shellcheck shell=bash

: "${SCRIPT_DIR:?}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Configuration
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="${PROJECT_DIR}/build"
QUICKWORK_BIN="${BUILD_DIR}/quickwork"
PORT="${TEST_PORT:-9999}"
PORT_SINGLE="${TEST_PORT_SINGLE:-9998}"  # Single-threaded server port for concurrency tests
HOST="127.0.0.1"
BASE_URL="http://${HOST}:${PORT}"
BASE_URL_SINGLE="http://${HOST}:${PORT_SINGLE}"  # Single-threaded server URL
VERBOSE=0
KEEP_SERVER=0
SPECIFIC_TEST=""
TIMEOUT=30

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

# Parse arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -v|--verbose)
                VERBOSE=1
                shift
                ;;
            -k|--keep)
                KEEP_SERVER=1
                shift
                ;;
            -p|--port)
                PORT="$2"
                BASE_URL="http://${HOST}:${PORT}"
                shift 2
                ;;
            -t|--test)
                SPECIFIC_TEST="$2"
                shift 2
                ;;
            -h|--help)
                head -20 "$0" | tail -16
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                exit 1
                ;;
        esac
    done
}

# Logging functions
log() { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[PASS]${NC} $*"; }
log_fail() { echo -e "${RED}[FAIL]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_debug() { [[ $VERBOSE -eq 1 ]] && echo -e "${CYAN}[DEBUG]${NC} $*" || true; }
log_section() { echo -e "\n${BOLD}${YELLOW}=== $* ===${NC}\n"; }

# Cleanup function
cleanup() {
    if [[ $KEEP_SERVER -eq 0 ]]; then
        if [[ -n "${SERVER_PID:-}" ]]; then
            log "Stopping server (PID: $SERVER_PID)..."
            kill "$SERVER_PID" 2>/dev/null || true
            wait "$SERVER_PID" 2>/dev/null || true
        fi
        if [[ -n "${SERVER_SINGLE_PID:-}" ]]; then
            log "Stopping single-threaded server (PID: $SERVER_SINGLE_PID)..."
            kill "$SERVER_SINGLE_PID" 2>/dev/null || true
            wait "$SERVER_SINGLE_PID" 2>/dev/null || true
        fi
    fi
}
trap cleanup EXIT

# Wait for server to be ready
wait_for_server() {
    local url="${1:-$BASE_URL}"
    local max_attempts=50
    local attempt=0

    while [[ $attempt -lt $max_attempts ]]; do
        if curl -s "${url}/health" > /dev/null 2>&1; then
            return 0
        fi
        sleep 0.1
        ((attempt++))
    done

    log_fail "Server failed to start within timeout"
    return 1
}

# Register a handler and return its ID
register_handler() {
    local handler_code="$1"
    local response

    response=$(curl -s -X POST "${BASE_URL}" \
        -H "Content-Type: application/javascript" \
        -d "$handler_code")

    echo "$response" | grep -o '"id":"[^"]*"' | cut -d'"' -f4
}

# Execute a handler with optional method, headers, and body
execute_handler() {
    local handler_id="$1"
    local method="${2:-GET}"
    local body="${3:-}"
    local extra_headers="${4:-}"

    local curl_args=(-s -X "$method")
    curl_args+=(-H "x-handler-id: $handler_id")

    if [[ -n "$extra_headers" ]]; then
        while IFS= read -r header; do
            [[ -n "$header" ]] && curl_args+=(-H "$header")
        done <<< "$extra_headers"
    fi

    if [[ -n "$body" ]]; then
        curl_args+=(-d "$body")
    fi

    curl "${curl_args[@]}" "${BASE_URL}/"
}

# Execute handler and return headers + body
execute_handler_with_headers() {
    local handler_id="$1"
    local method="${2:-GET}"
    local body="${3:-}"

    local curl_args=(-s -i -X "$method")
    curl_args+=(-H "x-handler-id: $handler_id")

    if [[ -n "$body" ]]; then
        curl_args+=(-d "$body")
    fi

    curl "${curl_args[@]}" "${BASE_URL}/"
}

# Test assertion functions
assert_equals() {
    local expected="$1"
    local actual="$2"
    local message="${3:-Values should be equal}"

    if [[ "$expected" == "$actual" ]]; then
        return 0
    else
        log_debug "Expected: $expected"
        log_debug "Actual: $actual"
        return 1
    fi
}

assert_contains() {
    local haystack="$1"
    local needle="$2"
    local message="${3:-Should contain substring}"

    if [[ "$haystack" == *"$needle"* ]]; then
        return 0
    else
        log_debug "Haystack: $haystack"
        log_debug "Looking for: $needle"
        return 1
    fi
}

assert_json_field() {
    local json="$1"
    local field="$2"
    local expected="$3"

    local actual
    actual=$(echo "$json" | grep -o "\"$field\":[^,}]*" | cut -d: -f2- | tr -d '"' | tr -d ' ')

    if [[ "$actual" == "$expected" ]]; then
        return 0
    else
        log_debug "JSON: $json"
        log_debug "Field '$field' expected: $expected, got: $actual"
        return 1
    fi
}

# Run a single test
run_test() {
    local test_name="$1"
    local test_func="$2"

    if [[ -n "$SPECIFIC_TEST" ]] && [[ "$test_name" != *"$SPECIFIC_TEST"* ]]; then
        return 0
    fi

    ((TESTS_RUN++))

    printf "  %-60s " "$test_name"

    if $test_func; then
        log_success "PASS"
        ((TESTS_PASSED++))
    else
        log_fail "FAIL"
        ((TESTS_FAILED++))
    fi
}
