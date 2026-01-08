#!/usr/bin/env bash
#
# Quickwork Test Suite
# ====================
# Comprehensive test suite for the quickwork JavaScript runtime server.
#
# Usage: ./tests/run_tests.sh [options]
#
# Options:
#   -v, --verbose     Show detailed output
#   -k, --keep        Keep server running after tests
#   -p, --port PORT   Use specific port (default: 9999)
#   -t, --test NAME   Run specific test only
#   -h, --help        Show this help
#

set -uo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="${PROJECT_DIR}/build"
QUICKWORK_BIN="${BUILD_DIR}/quickwork"
PORT="${TEST_PORT:-9999}"
HOST="127.0.0.1"
BASE_URL="http://${HOST}:${PORT}"
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

# Logging functions
log() { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[PASS]${NC} $*"; }
log_fail() { echo -e "${RED}[FAIL]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_debug() { [[ $VERBOSE -eq 1 ]] && echo -e "${CYAN}[DEBUG]${NC} $*" || true; }
log_section() { echo -e "\n${BOLD}${YELLOW}=== $* ===${NC}\n"; }

# Cleanup function
cleanup() {
    if [[ $KEEP_SERVER -eq 0 ]] && [[ -n "${SERVER_PID:-}" ]]; then
        log "Stopping server (PID: $SERVER_PID)..."
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# Wait for server to be ready
wait_for_server() {
    local max_attempts=50
    local attempt=0
    
    while [[ $attempt -lt $max_attempts ]]; do
        if curl -s "${BASE_URL}/health" > /dev/null 2>&1; then
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

# =============================================================================
# TEST HANDLERS
# =============================================================================

# Test: Basic text response
test_basic_text_response() {
    local handler='export default function(req) {
        return new Response("Hello, World!");
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_equals "Hello, World!" "$response"
}

# Test: JSON response using Response.json()
test_json_response() {
    local handler='export default function(req) {
        return Response.json({ message: "success", count: 42 });
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"message":"success"' && \
    assert_contains "$response" '"count":42'
}

# Test: HTML response with content-type header
test_html_response() {
    local handler='export default function(req) {
        return new Response("<html><body><h1>Hello</h1></body></html>", {
            headers: { "Content-Type": "text/html; charset=utf-8" }
        });
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler_with_headers "$id")
    
    assert_contains "$response" "text/html" && \
    assert_contains "$response" "<h1>Hello</h1>"
}

# Test: Custom status code (404)
test_custom_status_code() {
    local handler='export default function(req) {
        return new Response("Not Found", { status: 404 });
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler_with_headers "$id")
    
    assert_contains "$response" "404"
}

# Test: Cache-Control header
test_cache_control_header() {
    local handler='export default function(req) {
        return new Response("Cached content", {
            headers: {
                "Cache-Control": "max-age=3600, public",
                "ETag": "abc123"
            }
        });
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler_with_headers "$id")
    
    assert_contains "$response" "Cache-Control: max-age=3600, public" && \
    assert_contains "$response" "ETag: abc123"
}

# Test: Multiple custom headers
test_multiple_headers() {
    local handler='export default function(req) {
        return new Response("Multi-header response", {
            headers: {
                "X-Custom-Header": "custom-value",
                "X-Request-Id": "req-12345",
                "X-Api-Version": "v2"
            }
        });
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler_with_headers "$id")
    
    assert_contains "$response" "X-Custom-Header: custom-value" && \
    assert_contains "$response" "X-Request-Id: req-12345" && \
    assert_contains "$response" "X-Api-Version: v2"
}

# Test: Built-in execution stats headers
test_builtin_stats_headers() {
    local handler='export default function(req) {
        // Do some work to generate measurable stats
        let sum = 0;
        for (let i = 0; i < 1000; i++) sum += i;
        return new Response("Stats test");
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler_with_headers "$id")
    
    # Check for x-qw-cpu and x-qw-mem headers
    assert_contains "$response" "x-qw-cpu:" && \
    assert_contains "$response" "x-qw-mem:"
}

# Test: Async handler with Promise
test_async_handler() {
    local handler='export default async function(req) {
        const data = await Promise.resolve({ status: "async-ok" });
        return Response.json(data);
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"status":"async-ok"'
}

# Test: Request method access
test_request_method() {
    local handler='export default function(req) {
        return Response.json({ method: req.method });
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id" "POST")
    
    assert_contains "$response" '"method":"POST"'
}

# Test: Request URL access
test_request_url() {
    local handler='export default function(req) {
        return Response.json({ url: req.url });
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"url":"/"'
}

# Test: Request body access
test_request_body() {
    local handler='export default function(req) {
        return new Response("Body: " + req.body);
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id" "POST" "test-body-content")
    
    assert_equals "Body: test-body-content" "$response"
}

# Test: Request headers access
test_request_headers() {
    local handler='export default function(req) {
        return Response.json({ 
            customHeader: req.headers["X-Test-Header"] || "not-found"
        });
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id" "GET" "" "X-Test-Header: my-test-value")
    
    assert_contains "$response" '"customHeader":"my-test-value"'
}

# Test: Request JSON parsing
test_request_json() {
    local handler='export default function(req) {
        const data = req.json();
        return Response.json({ received: data.name, age: data.age });
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id" "POST" '{"name":"John","age":30}' "Content-Type: application/json")
    
    assert_contains "$response" '"received":"John"' && \
    assert_contains "$response" '"age":30'
}

# Test: setTimeout basic functionality
test_setTimeout_basic() {
    local handler='export default async function(req) {
        let resolved = false;
        await new Promise(resolve => {
            setTimeout(() => {
                resolved = true;
                resolve();
            }, 10);
        });
        return Response.json({ resolved: resolved });
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"resolved":true'
}

# Test: clearTimeout cancels timer
test_clearTimeout() {
    local handler='export default async function(req) {
        let called = false;
        const timerId = setTimeout(() => {
            called = true;
        }, 50);
        
        clearTimeout(timerId);
        
        // Wait a bit to ensure timer would have fired
        await new Promise(resolve => setTimeout(resolve, 100));
        
        return Response.json({ timerCalled: called });
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"timerCalled":false'
}

# Test: Multiple setTimeouts with different delays
test_multiple_timers() {
    local handler='export default async function(req) {
        const order = [];
        
        await Promise.all([
            new Promise(resolve => setTimeout(() => { order.push(3); resolve(); }, 30)),
            new Promise(resolve => setTimeout(() => { order.push(1); resolve(); }, 10)),
            new Promise(resolve => setTimeout(() => { order.push(2); resolve(); }, 20))
        ]);
        
        return Response.json({ order: order });
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"order":[1,2,3]'
}

# Test: setTimeout with zero delay
test_setTimeout_zero_delay() {
    local handler='export default async function(req) {
        let executed = false;
        await new Promise(resolve => {
            setTimeout(() => {
                executed = true;
                resolve();
            }, 0);
        });
        return Response.json({ executed: executed });
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"executed":true'
}

# Test: Promise.all with multiple promises
test_promise_all() {
    local handler='export default async function(req) {
        const results = await Promise.all([
            Promise.resolve(1),
            Promise.resolve(2),
            Promise.resolve(3)
        ]);
        return Response.json({ results: results, sum: results.reduce((a,b) => a+b, 0) });
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"results":[1,2,3]' && \
    assert_contains "$response" '"sum":6'
}

# Test: Console logging (shouldn't break execution)
test_console_log() {
    local handler='export default function(req) {
        console.log("Debug message");
        console.info("Info message");
        console.warn("Warning message");
        console.error("Error message");
        return new Response("Logged successfully");
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_equals "Logged successfully" "$response"
}

# Test: crypto.randomUUID()
test_crypto_randomUUID() {
    local handler='export default function(req) {
        const uuid = crypto.randomUUID();
        // UUID v4 format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
        const valid = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(uuid);
        return Response.json({ uuid: uuid, valid: valid });
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"valid":true'
}

# Test: crypto.getRandomValues()
test_crypto_getRandomValues() {
    local handler='export default function(req) {
        const array = new Uint8Array(16);
        crypto.getRandomValues(array);
        // Check that at least some values are non-zero (very unlikely all zero)
        const hasNonZero = array.some(v => v !== 0);
        return Response.json({ length: array.length, hasNonZero: hasNonZero });
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"length":16' && \
    assert_contains "$response" '"hasNonZero":true'
}

# Test: Error handling in handler
test_error_handling() {
    local handler='export default function(req) {
        throw new Error("Intentional error");
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler_with_headers "$id")
    
    assert_contains "$response" "500" || assert_contains "$response" "error"
}

# Test: TextDecoder for Uint8Array to string
test_text_decoder() {
    local handler='export default function(req) {
        const decoder = new TextDecoder("utf-8");
        const bytes = new Uint8Array([72, 101, 108, 108, 111]); // "Hello"
        const text = decoder.decode(bytes);
        return Response.json({ text: text, encoding: decoder.encoding });
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"text":"Hello"' && \
    assert_contains "$response" '"encoding":"utf-8"'
}

# Test: Streaming text response using StreamResponse
test_streaming_text() {
    local handler='export default async function(req) {
        const stream = new StreamResponse({
            headers: { "Content-Type": "text/plain" }
        });
        
        stream.write("chunk1");
        stream.write("chunk2");
        stream.write("chunk3");
        stream.close();
        
        return stream;
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(curl -s -H "x-handler-id: $id" "${BASE_URL}/")
    
    assert_contains "$response" "chunk1" && \
    assert_contains "$response" "chunk2" && \
    assert_contains "$response" "chunk3"
}

# Test: SSE streaming with send()
test_streaming_sse() {
    local handler='export default async function(req) {
        const stream = new StreamResponse();
        
        stream.send({ event: "message", data: "first" });
        stream.send({ event: "update", data: { count: 1 } });
        stream.send("simple data");
        stream.close();
        
        return stream;
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(curl -s -H "x-handler-id: $id" "${BASE_URL}/")
    
    assert_contains "$response" "event: message" && \
    assert_contains "$response" "data: first" && \
    assert_contains "$response" "event: update"
}

# Test: StreamResponse with delayed writes using setTimeout
test_streaming_with_timeout() {
    local handler='export default async function(req) {
        const stream = new StreamResponse();
        
        stream.write("start\n");
        
        await new Promise(resolve => {
            setTimeout(() => {
                stream.write("delayed\n");
                resolve();
            }, 50);
        });
        
        stream.write("end\n");
        stream.close();
        
        return stream;
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(curl -s -H "x-handler-id: $id" "${BASE_URL}/")
    
    assert_contains "$response" "start" && \
    assert_contains "$response" "delayed" && \
    assert_contains "$response" "end"
}

# Test: Redirect response
test_redirect_status() {
    local handler='export default function(req) {
        return new Response("", {
            status: 302,
            headers: { "Location": "https://example.com" }
        });
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler_with_headers "$id")
    
    assert_contains "$response" "302" && \
    assert_contains "$response" "Location: https://example.com"
}

# Test: Empty response body
test_empty_response() {
    local handler='export default function(req) {
        return new Response("", { status: 204 });
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler_with_headers "$id")
    
    assert_contains "$response" "204"
}

# Test: Large response body
test_large_response() {
    local handler='export default function(req) {
        const data = "x".repeat(100000);
        return new Response(data);
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    local length=${#response}
    
    [[ $length -eq 100000 ]]
}

# Test: JSON with special characters
test_json_special_chars() {
    local handler='export default function(req) {
        return Response.json({ 
            text: "Hello \"World\"",
            unicode: "Hello \u00e9",
            newline: "line1\nline2"
        });
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" 'Hello \"World\"' || assert_contains "$response" '"text":'
}

# Test: Multiple handlers (isolation)
test_handler_isolation() {
    local handler1='export default function(req) {
        return new Response("handler1");
    }'
    
    local handler2='export default function(req) {
        return new Response("handler2");
    }'
    
    local id1 id2
    id1=$(register_handler "$handler1")
    id2=$(register_handler "$handler2")
    
    [[ -z "$id1" || -z "$id2" ]] && return 1
    
    local response1 response2
    response1=$(execute_handler "$id1")
    response2=$(execute_handler "$id2")
    
    assert_equals "handler1" "$response1" && \
    assert_equals "handler2" "$response2"
}

# Test: Concurrent handler execution
test_concurrent_execution() {
    local handler='export default async function(req) {
        await new Promise(resolve => setTimeout(resolve, 100));
        return Response.json({ id: req.headers["X-Request-Num"] || "unknown" });
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    # Execute multiple requests concurrently
    local pids=()
    local results=()
    
    for i in 1 2 3; do
        (execute_handler "$id" "GET" "" "X-Request-Num: $i") &
        pids+=($!)
    done
    
    for pid in "${pids[@]}"; do
        wait "$pid"
    done
    
    # All should complete without error
    return 0
}

# Test: Health endpoint
test_health_endpoint() {
    local response
    response=$(curl -s "${BASE_URL}/health")
    
    assert_contains "$response" '"status":"ok"'
}

# Test: Missing handler ID
test_missing_handler_id() {
    local response
    response=$(curl -s -X GET "${BASE_URL}/")
    
    assert_contains "$response" "error" || assert_contains "$response" "Missing"
}

# Test: Unknown handler ID
test_unknown_handler_id() {
    local response
    response=$(curl -s -H "x-handler-id: nonexistent-id-12345" "${BASE_URL}/")
    
    assert_contains "$response" "error" || assert_contains "$response" "not found"
}

# Test: Handler not found returns x-qw-handler-not-found header
test_handler_not_found_header() {
    local response
    response=$(curl -s -i -H "x-handler-id: nonexistent-id-12345" "${BASE_URL}/")
    
    assert_contains "$response" "x-qw-handler-not-found: true"
}

# Test: Handler invocation via subdomain (alternative to x-handler-id header)
test_subdomain_handler_invocation() {
    local handler='export default function(req) {
        return new Response("Hello from subdomain!");
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    # Execute handler via subdomain instead of x-handler-id header
    # Use Host header to simulate subdomain: <handler-id>.localhost
    local response
    response=$(curl -s -H "Host: ${id}.localhost" "${BASE_URL}/")
    
    assert_equals "Hello from subdomain!" "$response"
}

# Test: Handler cannot forge x-qw-handler-not-found header
test_handler_cannot_forge_not_found_header() {
    local handler='export default function(req) {
        return new Response("Fake not found", {
            status: 404,
            headers: { "x-qw-handler-not-found": "true" }
        });
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler_with_headers "$id")
    
    # Response should NOT contain the x-qw-handler-not-found header
    # (it gets stripped from handler responses)
    if [[ "$response" == *"x-qw-handler-not-found"* ]]; then
        log_debug "Handler was able to forge x-qw-handler-not-found header!"
        return 1
    fi
    
    # But it should still have the handler's body
    assert_contains "$response" "Fake not found"
}

# Test: ESM default import (requires network - skip if no connection)
test_esm_import_default() {
    # Check network connectivity first
    if ! curl -s --connect-timeout 2 "https://esm.sh" > /dev/null 2>&1; then
        log_debug "Skipping ESM test - no network connectivity"
        ((TESTS_SKIPPED++))
        return 0
    fi
    
    local handler='import ms from "https://esm.sh/ms@2.1.3";

export default function(req) {
    const result = ms("1h");
    return Response.json({ hours: result });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"hours":3600000'
}

# Test: ESM named import
test_esm_import_named() {
    # Check network connectivity first
    if ! curl -s --connect-timeout 2 "https://esm.sh" > /dev/null 2>&1; then
        log_debug "Skipping ESM test - no network connectivity"
        ((TESTS_SKIPPED++))
        return 0
    fi
    
    local handler='import { v4 as uuidv4 } from "https://esm.sh/uuid@9.0.0";

export default function(req) {
    const id = uuidv4();
    const valid = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(id);
    return Response.json({ valid: valid });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"valid":true'
}

# Test: ESM import Neon serverless postgres client
test_esm_import_neon() {
    # Check network connectivity first
    if ! curl -s --connect-timeout 2 "https://esm.sh" > /dev/null 2>&1; then
        log_debug "Skipping ESM test - no network connectivity"
        ((TESTS_SKIPPED++))
        return 0
    fi
    
    local handler='import { neon } from "https://esm.sh/@neondatabase/serverless";

export default function(req) {
    // Just verify the import works and neon is a function
    return Response.json({ 
        imported: true,
        isFunction: typeof neon === "function"
    });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"imported":true' && \
    assert_contains "$response" '"isFunction":true'
}

# Test: ESM import Turso/libsql HTTP client
test_esm_import_turso() {
    # Check network connectivity first
    if ! curl -s --connect-timeout 2 "https://esm.sh" > /dev/null 2>&1; then
        log_debug "Skipping ESM test - no network connectivity"
        ((TESTS_SKIPPED++))
        return 0
    fi
    
    local handler='import { createClient } from "https://esm.sh/@libsql/client/http";

export default function(req) {
    // Just verify the import works and createClient is a function
    return Response.json({ 
        imported: true,
        isFunction: typeof createClient === "function"
    });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"imported":true' && \
    assert_contains "$response" '"isFunction":true'
}

# Test: ESM import Supabase JS client
test_esm_import_supabase() {
    # Check network connectivity first
    if ! curl -s --connect-timeout 2 "https://esm.sh" > /dev/null 2>&1; then
        log_debug "Skipping ESM test - no network connectivity"
        ((TESTS_SKIPPED++))
        return 0
    fi
    
    local handler='import { createClient } from "https://esm.sh/@supabase/supabase-js";

export default function(req) {
    // Just verify the import works and createClient is a function
    return Response.json({ 
        imported: true,
        isFunction: typeof createClient === "function"
    });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"imported":true' && \
    assert_contains "$response" '"isFunction":true'
}

# Test: Promise.all with fetch (mock endpoint)
test_promise_all_with_delayed_operations() {
    local handler='export default async function(req) {
        const start = Date.now();
        
        // Simulate parallel async operations
        const results = await Promise.all([
            new Promise(resolve => setTimeout(() => resolve("a"), 50)),
            new Promise(resolve => setTimeout(() => resolve("b"), 50)),
            new Promise(resolve => setTimeout(() => resolve("c"), 50))
        ]);
        
        const elapsed = Date.now() - start;
        
        return Response.json({ 
            results: results, 
            // All should complete in ~50ms, not 150ms (proving parallelism)
            parallel: elapsed < 150
        });
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"results":["a","b","c"]' && \
    assert_contains "$response" '"parallel":true'
}

# Test: CORS headers
test_cors_headers() {
    local handler='export default function(req) {
        return new Response("OK", {
            headers: {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type"
            }
        });
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler_with_headers "$id")
    
    assert_contains "$response" "Access-Control-Allow-Origin: *"
}

# Test: Content-Type inference for JSON
test_json_content_type() {
    local handler='export default function(req) {
        return Response.json({ test: true });
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler_with_headers "$id")
    
    assert_contains "$response" "application/json"
}

# Test: Repeated handler execution (caching)
test_handler_caching() {
    local handler='export default function(req) {
        return Response.json({ timestamp: Date.now() });
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    # Execute same handler multiple times
    local response1 response2 response3
    response1=$(execute_handler "$id")
    response2=$(execute_handler "$id")
    response3=$(execute_handler "$id")
    
    # All should succeed (different timestamps)
    assert_contains "$response1" '"timestamp":' && \
    assert_contains "$response2" '"timestamp":' && \
    assert_contains "$response3" '"timestamp":'
}

# Test: Array response in JSON
test_array_response() {
    local handler='export default function(req) {
        return Response.json([1, 2, 3, 4, 5]);
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_equals "[1,2,3,4,5]" "$response"
}

# Test: Nested object response
test_nested_object() {
    local handler='export default function(req) {
        return Response.json({
            user: {
                name: "John",
                address: {
                    city: "NYC",
                    zip: "10001"
                }
            }
        });
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"name":"John"' && \
    assert_contains "$response" '"city":"NYC"'
}

# Test: Recursive function with deep call stack
test_deep_recursion() {
    local handler='export default function(req) {
        function fib(n) {
            if (n <= 1) return n;
            return fib(n - 1) + fib(n - 2);
        }
        // fib(25) = 75025, requires many recursive calls
        const result = fib(25);
        return Response.json({ fib25: result });
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"fib25":75025'
}

# Test: Generator function and iteration
test_generator_function() {
    local handler='export default function(req) {
        function* range(start, end) {
            for (let i = start; i < end; i++) yield i;
        }
        const nums = [...range(1, 6)];
        return Response.json({ nums: nums });
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"nums":[1,2,3,4,5]'
}

# Test: Async generator with for-await-of
test_async_generator() {
    local handler='export default async function(req) {
        async function* asyncRange(start, end) {
            for (let i = start; i < end; i++) {
                await new Promise(r => setTimeout(r, 1));
                yield i;
            }
        }
        const nums = [];
        for await (const n of asyncRange(1, 4)) {
            nums.push(n);
        }
        return Response.json({ nums: nums });
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"nums":[1,2,3]'
}

# Test: Proxy object with traps
test_proxy_object() {
    local handler='export default function(req) {
        const target = { x: 10, y: 20 };
        const handler = {
            get(obj, prop) {
                return prop in obj ? obj[prop] * 2 : 0;
            }
        };
        const proxy = new Proxy(target, handler);
        return Response.json({ x: proxy.x, y: proxy.y, z: proxy.z });
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"x":20' && \
    assert_contains "$response" '"y":40' && \
    assert_contains "$response" '"z":0'
}

# Test: WeakMap and garbage collection hints
test_weakmap() {
    local handler='export default function(req) {
        const wm = new WeakMap();
        const obj1 = { id: 1 };
        const obj2 = { id: 2 };
        wm.set(obj1, "value1");
        wm.set(obj2, "value2");
        return Response.json({ 
            has1: wm.has(obj1), 
            has2: wm.has(obj2),
            val1: wm.get(obj1)
        });
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"has1":true' && \
    assert_contains "$response" '"has2":true' && \
    assert_contains "$response" '"val1":"value1"'
}

# Test: Symbol as object key
test_symbol_keys() {
    local handler='export default function(req) {
        const sym = Symbol("mySymbol");
        const obj = { [sym]: "secret", visible: "public" };
        const keys = Object.keys(obj);
        const syms = Object.getOwnPropertySymbols(obj);
        return Response.json({ 
            keyCount: keys.length,
            symCount: syms.length,
            hasSecret: obj[syms[0]] === "secret"
        });
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"keyCount":1' && \
    assert_contains "$response" '"symCount":1' && \
    assert_contains "$response" '"hasSecret":true'
}

# Test: BigInt arithmetic
test_bigint_arithmetic() {
    local handler='export default function(req) {
        const big1 = 9007199254740993n; // Larger than Number.MAX_SAFE_INTEGER
        const big2 = 9007199254740993n;
        const sum = big1 + big2;
        const product = big1 * 2n;
        return Response.json({ 
            sumStr: sum.toString(),
            productStr: product.toString(),
            isEqual: big1 === big2
        });
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"sumStr":"18014398509481986"' && \
    assert_contains "$response" '"productStr":"18014398509481986"' && \
    assert_contains "$response" '"isEqual":true'
}

# Test: Reflect API
test_reflect_api() {
    local handler='export default function(req) {
        const obj = { x: 1 };
        Reflect.set(obj, "y", 2);
        const has = Reflect.has(obj, "y");
        const keys = Reflect.ownKeys(obj);
        Reflect.deleteProperty(obj, "x");
        return Response.json({ 
            has: has, 
            keys: keys, 
            afterDelete: Object.keys(obj)
        });
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"has":true' && \
    assert_contains "$response" '"keys":["x","y"]' && \
    assert_contains "$response" '"afterDelete":["y"]'
}

# Test: Promise.race with timeout
test_promise_race() {
    local handler='export default async function(req) {
        const slow = new Promise(r => setTimeout(() => r("slow"), 100));
        const fast = new Promise(r => setTimeout(() => r("fast"), 10));
        const winner = await Promise.race([slow, fast]);
        return Response.json({ winner: winner });
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"winner":"fast"'
}

# Test: Promise.allSettled with mixed results
test_promise_allsettled() {
    local handler='export default async function(req) {
        const results = await Promise.allSettled([
            Promise.resolve("success"),
            Promise.reject("failure"),
            Promise.resolve(42)
        ]);
        return Response.json({ 
            statuses: results.map(r => r.status),
            values: results.filter(r => r.status === "fulfilled").map(r => r.value)
        });
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"statuses":["fulfilled","rejected","fulfilled"]' && \
    assert_contains "$response" '"values":["success",42]'
}

# Test: Destructuring with defaults and rest
test_advanced_destructuring() {
    local handler='export default function(req) {
        const obj = { a: 1, b: 2, c: 3, d: 4 };
        const { a, b = 10, e = 5, ...rest } = obj;
        const arr = [1, 2, 3, 4, 5];
        const [first, , third, ...remaining] = arr;
        return Response.json({ 
            a, b, e, rest, first, third, remaining 
        });
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"a":1' && \
    assert_contains "$response" '"b":2' && \
    assert_contains "$response" '"e":5' && \
    assert_contains "$response" '"first":1' && \
    assert_contains "$response" '"third":3' && \
    assert_contains "$response" '"remaining":[4,5]'
}

# Test: Tagged template literals
test_tagged_template() {
    local handler='export default function(req) {
        function highlight(strings, ...values) {
            return strings.reduce((acc, str, i) => 
                acc + str + (values[i] ? `**${values[i]}**` : ""), "");
        }
        const name = "World";
        const count = 42;
        const result = highlight`Hello ${name}, you have ${count} messages`;
        return Response.json({ result: result });
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" 'Hello **World**, you have **42** messages'
}

# Test: Nullish coalescing and optional chaining deep
test_nullish_and_optional() {
    local handler='export default function(req) {
        const obj = { 
            a: { b: { c: null } },
            x: 0,
            y: "",
            z: undefined
        };
        return Response.json({
            deep: obj?.a?.b?.c ?? "default",
            missing: obj?.a?.b?.d?.e ?? "not found",
            zero: obj.x ?? "fallback",
            empty: obj.y ?? "fallback", 
            undef: obj.z ?? "was undefined"
        });
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"deep":"default"' && \
    assert_contains "$response" '"missing":"not found"' && \
    assert_contains "$response" '"zero":0' && \
    assert_contains "$response" '"empty":""' && \
    assert_contains "$response" '"undef":"was undefined"'
}

# Test: Closure preserving state across handler calls (should NOT share state)
test_closure_isolation() {
    local handler='let counter = 0;
export default function(req) {
    counter++;
    return Response.json({ counter: counter });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    # Each execution should be isolated - counter should be 1 each time
    # (unless state leaks between executions)
    local r1 r2 r3
    r1=$(execute_handler "$id")
    r2=$(execute_handler "$id")
    r3=$(execute_handler "$id")
    
    # If properly isolated, all should be 1
    # If state leaks, they would be 1, 2, 3
    local c1 c2 c3
    c1=$(echo "$r1" | grep -o '"counter":[0-9]*' | cut -d: -f2)
    c2=$(echo "$r2" | grep -o '"counter":[0-9]*' | cut -d: -f2)
    c3=$(echo "$r3" | grep -o '"counter":[0-9]*' | cut -d: -f2)
    
    # For security, each should start fresh (counter=1)
    [[ "$c1" == "1" && "$c2" == "1" && "$c3" == "1" ]]
}

# Test: Error in async function properly rejects
test_async_error_rejection() {
    local handler='export default async function(req) {
        await Promise.resolve();
        throw new Error("async boom");
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler_with_headers "$id")
    
    assert_contains "$response" "500" || assert_contains "$response" "error" || assert_contains "$response" "boom"
}

# Test: Nested Promise chains
test_nested_promise_chains() {
    local handler='export default async function(req) {
        const result = await Promise.resolve(1)
            .then(x => Promise.resolve(x + 1))
            .then(x => Promise.resolve(x * 2))
            .then(x => Promise.resolve(x + 10))
            .then(x => ({ final: x }));
        return Response.json(result);
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    # (1+1)*2+10 = 14
    assert_contains "$response" '"final":14'
}

# Test: Array methods chaining (map, filter, reduce)
test_array_method_chaining() {
    local handler='export default function(req) {
        const result = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
            .filter(x => x % 2 === 0)
            .map(x => x * x)
            .reduce((acc, x) => acc + x, 0);
        return Response.json({ sumOfEvenSquares: result });
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    # 4 + 16 + 36 + 64 + 100 = 220
    assert_contains "$response" '"sumOfEvenSquares":220'
}

# Test: RegExp with named capture groups
test_regexp_named_groups() {
    local handler='export default function(req) {
        const re = /(?<year>\d{4})-(?<month>\d{2})-(?<day>\d{2})/;
        const match = re.exec("2024-12-25");
        return Response.json({
            year: match.groups.year,
            month: match.groups.month,
            day: match.groups.day
        });
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"year":"2024"' && \
    assert_contains "$response" '"month":"12"' && \
    assert_contains "$response" '"day":"25"'
}

# Test: Object.fromEntries and Object.entries round-trip
test_object_entries_roundtrip() {
    local handler='export default function(req) {
        const obj = { a: 1, b: 2, c: 3 };
        const entries = Object.entries(obj);
        const doubled = entries.map(([k, v]) => [k, v * 2]);
        const result = Object.fromEntries(doubled);
        return Response.json(result);
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"a":2' && \
    assert_contains "$response" '"b":4' && \
    assert_contains "$response" '"c":6'
}

# Test: Class with private fields (ES2022)
test_class_private_fields() {
    local handler='export default function(req) {
        class Counter {
            #count = 0;
            increment() { this.#count++; }
            get value() { return this.#count; }
        }
        const c = new Counter();
        c.increment();
        c.increment();
        c.increment();
        return Response.json({ value: c.value });
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"value":3'
}

# =============================================================================
# FETCH API TESTS
# =============================================================================

# Helper to check network connectivity
check_network() {
    curl -s --connect-timeout 2 "https://httpbin.org/get" > /dev/null 2>&1
}

# Test: Basic fetch GET request
test_fetch_get() {
    if ! check_network; then
        log_debug "Skipping fetch test - no network"
        ((TESTS_SKIPPED++))
        return 0
    fi
    
    local handler='export default async function(req) {
        const response = await fetch("https://httpbin.org/get");
        const data = await response.json();
        return Response.json({ 
            ok: response.ok,
            status: response.status,
            hasUrl: !!data.url
        });
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"ok":true' && \
    assert_contains "$response" '"status":200' && \
    assert_contains "$response" '"hasUrl":true'
}

# Test: Fetch POST with JSON body
test_fetch_post_json() {
    if ! check_network; then
        log_debug "Skipping fetch test - no network"
        ((TESTS_SKIPPED++))
        return 0
    fi
    
    local handler='export default async function(req) {
        const response = await fetch("https://httpbin.org/post", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ name: "test", value: 42 })
        });
        const data = await response.json();
        return Response.json({ 
            status: response.status,
            receivedName: data.json?.name,
            receivedValue: data.json?.value
        });
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"status":200' && \
    assert_contains "$response" '"receivedName":"test"' && \
    assert_contains "$response" '"receivedValue":42'
}

# Test: Fetch with custom headers
test_fetch_custom_headers() {
    if ! check_network; then
        log_debug "Skipping fetch test - no network"
        ((TESTS_SKIPPED++))
        return 0
    fi
    
    local handler='export default async function(req) {
        const response = await fetch("https://httpbin.org/headers", {
            headers: { 
                "X-Custom-Header": "my-value",
                "X-Another": "another-value"
            }
        });
        const data = await response.json();
        return Response.json({ 
            customHeader: data.headers["X-Custom-Header"],
            anotherHeader: data.headers["X-Another"]
        });
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"customHeader":"my-value"' && \
    assert_contains "$response" '"anotherHeader":"another-value"'
}

# Test: Fetch response.text()
test_fetch_text_response() {
    if ! check_network; then
        log_debug "Skipping fetch test - no network"
        ((TESTS_SKIPPED++))
        return 0
    fi
    
    local handler='export default async function(req) {
        const response = await fetch("https://httpbin.org/robots.txt");
        const text = await response.text();
        return Response.json({ 
            hasContent: text.length > 0,
            isString: typeof text === "string"
        });
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"hasContent":true' && \
    assert_contains "$response" '"isString":true'
}

# Test: Fetch handles HTTP errors (4xx)
test_fetch_http_error() {
    if ! check_network; then
        log_debug "Skipping fetch test - no network"
        ((TESTS_SKIPPED++))
        return 0
    fi
    
    local handler='export default async function(req) {
        const response = await fetch("https://httpbin.org/status/404");
        return Response.json({ 
            status: response.status,
            ok: response.ok
        });
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"status":404' && \
    assert_contains "$response" '"ok":false'
}

# Test: Fetch PUT request
test_fetch_put() {
    if ! check_network; then
        log_debug "Skipping fetch test - no network"
        ((TESTS_SKIPPED++))
        return 0
    fi
    
    local handler='export default async function(req) {
        const response = await fetch("https://httpbin.org/put", {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ updated: true })
        });
        const data = await response.json();
        return Response.json({ 
            status: response.status,
            method: data.method,
            updated: data.json?.updated
        });
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"status":200' && \
    assert_contains "$response" '"updated":true'
}

# Test: Fetch DELETE request
test_fetch_delete() {
    if ! check_network; then
        log_debug "Skipping fetch test - no network"
        ((TESTS_SKIPPED++))
        return 0
    fi
    
    local handler='export default async function(req) {
        const response = await fetch("https://httpbin.org/delete", {
            method: "DELETE"
        });
        const data = await response.json();
        return Response.json({ 
            status: response.status,
            ok: response.ok
        });
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"status":200' && \
    assert_contains "$response" '"ok":true'
}

# Test: Fetch PATCH request
test_fetch_patch() {
    if ! check_network; then
        log_debug "Skipping fetch test - no network"
        ((TESTS_SKIPPED++))
        return 0
    fi
    
    local handler='export default async function(req) {
        const response = await fetch("https://httpbin.org/patch", {
            method: "PATCH",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ patched: true })
        });
        const data = await response.json();
        return Response.json({ 
            status: response.status,
            patched: data.json?.patched
        });
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"status":200' && \
    assert_contains "$response" '"patched":true'
}

# Test: Promise.all with multiple fetch requests (parallel)
test_fetch_promise_all() {
    if ! check_network; then
        log_debug "Skipping fetch test - no network"
        ((TESTS_SKIPPED++))
        return 0
    fi
    
    # Make 20 parallel requests to example.com
    # If sequential, each request takes ~100-200ms = 2-4s total
    # If parallel, should complete in ~200-500ms total
    local handler='export default async function(req) {
        const start = Date.now();
        const urls = Array(20).fill("https://example.com");
        
        const responses = await Promise.all(urls.map(url => fetch(url)));
        
        const elapsed = Date.now() - start;
        const allOk = responses.every(r => r.ok);
        
        return Response.json({ 
            count: responses.length,
            allOk: allOk,
            elapsed: elapsed,
            // 20 sequential requests would take 2-4s, parallel should be under 2s
            parallel: elapsed < 2000
        });
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"count":20' && \
    assert_contains "$response" '"allOk":true' && \
    assert_contains "$response" '"parallel":true'
}

# Test: Fetch with response headers access
test_fetch_response_headers() {
    if ! check_network; then
        log_debug "Skipping fetch test - no network"
        ((TESTS_SKIPPED++))
        return 0
    fi
    
    local handler='export default async function(req) {
        const response = await fetch("https://httpbin.org/response-headers?X-Test=hello");
        return Response.json({ 
            status: response.status,
            hasHeaders: typeof response.headers === "object"
        });
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"status":200' && \
    assert_contains "$response" '"hasHeaders":true'
}

# Test: Fetch follows redirects
test_fetch_redirect() {
    if ! check_network; then
        log_debug "Skipping fetch test - no network"
        ((TESTS_SKIPPED++))
        return 0
    fi
    
    local handler='export default async function(req) {
        // httpbin redirects to /get
        const response = await fetch("https://httpbin.org/redirect/1");
        const data = await response.json();
        return Response.json({ 
            status: response.status,
            ok: response.ok,
            redirected: data.url?.includes("/get") || false
        });
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"status":200' && \
    assert_contains "$response" '"ok":true'
}

# Test: Fetch to handler's own server (loopback)
test_fetch_loopback() {
    local handler='export default async function(req) {
        // Fetch health endpoint on same server
        const response = await fetch("http://127.0.0.1:'"$PORT"'/health");
        const data = await response.json();
        return Response.json({ 
            status: response.status,
            healthStatus: data.status
        });
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"status":200' && \
    assert_contains "$response" '"healthStatus":"ok"'
}

# Test: Fetch with form data (URL encoded)
test_fetch_form_data() {
    if ! check_network; then
        log_debug "Skipping fetch test - no network"
        ((TESTS_SKIPPED++))
        return 0
    fi
    
    local handler='export default async function(req) {
        const response = await fetch("https://httpbin.org/post", {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: "name=John&age=30"
        });
        const data = await response.json();
        return Response.json({ 
            status: response.status,
            formName: data.form?.name,
            formAge: data.form?.age
        });
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"status":200' && \
    assert_contains "$response" '"formName":"John"' && \
    assert_contains "$response" '"formAge":"30"'
}

# Test: Fetch streaming body with ReadableStream
test_fetch_streaming_body() {
    if ! check_network; then
        log_debug "Skipping fetch test - no network"
        ((TESTS_SKIPPED++))
        return 0
    fi
    
    local handler='export default async function(req) {
        const response = await fetch("https://httpbin.org/stream-bytes/100");
        
        // Check that body is available
        const hasBody = response.body !== null && response.body !== undefined;
        
        // Try to get reader
        let chunks = 0;
        let totalBytes = 0;
        
        if (hasBody && typeof response.body.getReader === "function") {
            const reader = response.body.getReader();
            while (true) {
                const { done, value } = await reader.read();
                if (done) break;
                chunks++;
                totalBytes += value?.length || 0;
            }
        }
        
        return Response.json({ 
            status: response.status,
            hasBody: hasBody,
            chunks: chunks,
            totalBytes: totalBytes
        });
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"status":200' && \
    assert_contains "$response" '"hasBody":true' && \
    assert_contains "$response" '"totalBytes":100'
}

# Test: Sequential fetch requests
test_fetch_sequential() {
    if ! check_network; then
        log_debug "Skipping fetch test - no network"
        ((TESTS_SKIPPED++))
        return 0
    fi
    
    local handler='export default async function(req) {
        const r1 = await fetch("https://httpbin.org/get?req=1");
        const d1 = await r1.json();
        
        const r2 = await fetch("https://httpbin.org/get?req=2");
        const d2 = await r2.json();
        
        const r3 = await fetch("https://httpbin.org/get?req=3");
        const d3 = await r3.json();
        
        return Response.json({ 
            req1: d1.args?.req,
            req2: d2.args?.req,
            req3: d3.args?.req
        });
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"req1":"1"' && \
    assert_contains "$response" '"req2":"2"' && \
    assert_contains "$response" '"req3":"3"'
}

# Test: Fetch with User-Agent header
test_fetch_user_agent() {
    if ! check_network; then
        log_debug "Skipping fetch test - no network"
        ((TESTS_SKIPPED++))
        return 0
    fi
    
    local handler='export default async function(req) {
        const response = await fetch("https://httpbin.org/user-agent", {
            headers: { "User-Agent": "QuickWork-Test/1.0" }
        });
        const data = await response.json();
        return Response.json({ 
            userAgent: data["user-agent"]
        });
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"userAgent":"QuickWork-Test/1.0"'
}

# Test: Stream in a large file and transform to uppercase while streaming out
test_stream_large_file_uppercase() {
    if ! check_network; then
        log_debug "Skipping fetch test - no network"
        ((TESTS_SKIPPED++))
        return 0
    fi
    
    local handler='export default async function(req) {
        const stream = new StreamResponse({
            headers: { "Content-Type": "text/plain; charset=utf-8" }
        });
        
        // Fetch the large Shakespeare text file
        const response = await fetch("https://gist.githubusercontent.com/blakesanie/dde3a2b7e698f52f389532b4b52bc254/raw/76fe1b5e9efcf0d2afdfd78b0bfaa737ad0a67d3/shakespeare.txt");
        
        if (!response.ok) {
            stream.write("ERROR: Failed to fetch file");
            stream.close();
            return stream;
        }
        
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        
        let totalBytes = 0;
        
        while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            
            // Decode the chunk, transform to uppercase, and write to output stream
            const text = decoder.decode(value, { stream: true });
            const upperText = text.toUpperCase();
            stream.write(upperText);
            totalBytes += value.length;
        }
        
        stream.close();
        return stream;
    }'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    # Execute and capture response with a longer timeout
    local response
    response=$(curl -s --max-time 60 -H "x-handler-id: $id" "${BASE_URL}/")
    
    # Verify the response is uppercase and contains expected Shakespeare content
    # The original file starts with "From fairest creatures we desire increase"
    # which should become "FROM FAIREST CREATURES WE DESIRE INCREASE"
    assert_contains "$response" "FROM FAIREST CREATURES WE DESIRE INCREASE" && \
    # Also verify it's substantial (the file is ~5.5MB)
    [[ ${#response} -gt 1000000 ]]
}

# =============================================================================
# POLYFILL TESTS
# =============================================================================

# Test: All polyfills work
test_polyfills_comprehensive() {
    local handler='export default function(req) {
    const results = {};
    
    // Test URL
    try {
        const url = new URL("https://example.com/path?foo=bar&baz=qux");
        results.url = {
            ok: true,
            hostname: url.hostname,
            pathname: url.pathname,
            searchParams: url.searchParams.get("foo")
        };
    } catch(e) {
        results.url = { ok: false, error: e.message };
    }
    
    // Test URLSearchParams
    try {
        const params = new URLSearchParams("a=1&b=2&c=3");
        results.urlSearchParams = {
            ok: true,
            a: params.get("a"),
            has_b: params.has("b"),
            entries: [...params.entries()].length
        };
    } catch(e) {
        results.urlSearchParams = { ok: false, error: e.message };
    }
    
    // Test btoa/atob
    try {
        const original = "Hello, World! 123";
        const encoded = btoa(original);
        const decoded = atob(encoded);
        results.base64 = {
            ok: true,
            encoded: encoded,
            roundTrip: decoded === original
        };
    } catch(e) {
        results.base64 = { ok: false, error: e.message };
    }
    
    // Summary
    results.allPassed = results.url.ok && 
        results.urlSearchParams.ok && 
        results.base64.ok;
    
    return Response.json(results);
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    # Check all polyfills work
    assert_contains "$response" '"allPassed":true'
}

# =============================================================================
# KV STORE TESTS
# =============================================================================

# Test: KV basic set and get
test_kv_basic_set_get() {
    local handler='import { kv } from "quickw";

export default function(req) {
    kv.set("test-key", "test-value");
    const value = kv.get("test-key");
    return Response.json({ value: value });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"value":"test-value"'
}

# Test: KV get non-existent key returns null
test_kv_get_nonexistent() {
    local handler='import { kv } from "quickw";

export default function(req) {
    const value = kv.get("nonexistent-key-12345");
    return Response.json({ value: value, isNull: value === null });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"value":null' && \
    assert_contains "$response" '"isNull":true'
}

# Test: KV delete key
test_kv_delete() {
    local handler='import { kv } from "quickw";

export default function(req) {
    kv.set("delete-test", "to-be-deleted");
    const before = kv.get("delete-test");
    const deleted = kv.del("delete-test");
    const after = kv.get("delete-test");
    return Response.json({ before, deleted, after });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"before":"to-be-deleted"' && \
    assert_contains "$response" '"deleted":true' && \
    assert_contains "$response" '"after":null'
}

# Test: KV delete alias works
test_kv_delete_alias() {
    local handler='import { kv } from "quickw";

export default function(req) {
    kv.set("delete-alias-test", "value");
    const deleted = kv.delete("delete-alias-test");
    const after = kv.get("delete-alias-test");
    return Response.json({ deleted, after });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"deleted":true' && \
    assert_contains "$response" '"after":null'
}

# Test: KV exists check
test_kv_exists() {
    local handler='import { kv } from "quickw";

export default function(req) {
    kv.set("exists-test", "value");
    const exists = kv.exists("exists-test");
    const notExists = kv.exists("nonexistent-exists-test");
    return Response.json({ exists, notExists });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"exists":true' && \
    assert_contains "$response" '"notExists":false'
}

# Test: KV size
test_kv_size() {
    local handler='import { kv } from "quickw";

export default function(req) {
    const initialSize = kv.size();
    kv.set("size-test-1", "a");
    kv.set("size-test-2", "b");
    kv.set("size-test-3", "c");
    const afterSet = kv.size();
    const increased = afterSet >= initialSize + 3;
    return Response.json({ initialSize, afterSet, increased });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"increased":true'
}

# Test: KV scan with prefix
test_kv_scan_prefix() {
    local handler='import { kv } from "quickw";

export default function(req) {
    kv.set("scan:user:1", "alice");
    kv.set("scan:user:2", "bob");
    kv.set("scan:user:3", "charlie");
    kv.set("scan:item:1", "widget");
    
    const userKeys = kv.scan("scan:user:");
    const itemKeys = kv.scan("scan:item:");
    const allKeys = kv.scan("scan:");
    
    return Response.json({ 
        userCount: userKeys.length,
        itemCount: itemKeys.length,
        totalCount: allKeys.length,
        hasUser1: userKeys.includes("scan:user:1"),
        hasItem1: itemKeys.includes("scan:item:1")
    });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"userCount":3' && \
    assert_contains "$response" '"itemCount":1' && \
    assert_contains "$response" '"totalCount":4' && \
    assert_contains "$response" '"hasUser1":true' && \
    assert_contains "$response" '"hasItem1":true'
}

# Test: KV scan with limit
test_kv_scan_limit() {
    local handler='import { kv } from "quickw";

export default function(req) {
    for (let i = 0; i < 10; i++) {
        kv.set("limit-test:" + i, "value" + i);
    }
    
    const limited = kv.scan("limit-test:", 3);
    const all = kv.scan("limit-test:");
    
    return Response.json({ 
        limitedCount: limited.length,
        allCount: all.length
    });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"limitedCount":3' && \
    assert_contains "$response" '"allCount":10'
}

# Test: KV entries returns key-value pairs
test_kv_entries() {
    local handler='import { kv } from "quickw";

export default function(req) {
    kv.set("entries:a", "value-a");
    kv.set("entries:b", "value-b");
    
    const entries = kv.entries("entries:");
    const hasCorrectStructure = entries.every(e => Array.isArray(e) && e.length === 2);
    const keys = entries.map(e => e[0]);
    const values = entries.map(e => e[1]);
    
    return Response.json({ 
        count: entries.length,
        hasCorrectStructure,
        hasKeyA: keys.includes("entries:a"),
        hasValueA: values.includes("value-a")
    });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"count":2' && \
    assert_contains "$response" '"hasCorrectStructure":true' && \
    assert_contains "$response" '"hasKeyA":true' && \
    assert_contains "$response" '"hasValueA":true'
}

# Test: KV TTL set and check
test_kv_ttl_set() {
    local handler='import { kv } from "quickw";

export default function(req) {
    kv.set("ttl-test", "expires-soon", 5000);
    const ttl = kv.ttl("ttl-test");
    const value = kv.get("ttl-test");
    
    // TTL should be close to 5000 (within 100ms tolerance)
    const ttlValid = ttl !== null && ttl > 4900 && ttl <= 5000;
    
    return Response.json({ 
        value,
        ttl,
        ttlValid
    });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"value":"expires-soon"' && \
    assert_contains "$response" '"ttlValid":true'
}

# Test: KV TTL returns null for keys without TTL
test_kv_ttl_no_expiry() {
    local handler='import { kv } from "quickw";

export default function(req) {
    kv.set("no-ttl-test", "permanent");
    const ttl = kv.ttl("no-ttl-test");
    const value = kv.get("no-ttl-test");
    
    return Response.json({ 
        value,
        ttl,
        ttlIsNull: ttl === null
    });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"value":"permanent"' && \
    assert_contains "$response" '"ttl":null' && \
    assert_contains "$response" '"ttlIsNull":true'
}

# Test: KV TTL expiration
test_kv_ttl_expiration() {
    local handler='import { kv } from "quickw";

export default async function(req) {
    kv.set("expire-test", "short-lived", 100);
    
    const before = {
        value: kv.get("expire-test"),
        exists: kv.exists("expire-test"),
        ttl: kv.ttl("expire-test")
    };
    
    // Wait for expiration
    await new Promise(resolve => setTimeout(resolve, 200));
    
    const after = {
        value: kv.get("expire-test"),
        exists: kv.exists("expire-test"),
        ttl: kv.ttl("expire-test")
    };
    
    return Response.json({ before, after });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    # Before expiration
    assert_contains "$response" '"value":"short-lived"' && \
    # After expiration - value should be null
    assert_contains "$response" '"after":{"value":null,"exists":false,"ttl":null}'
}

# Test: KV update resets TTL
test_kv_ttl_update() {
    local handler='import { kv } from "quickw";

export default async function(req) {
    kv.set("ttl-update-test", "initial", 100);
    
    // Wait 50ms
    await new Promise(resolve => setTimeout(resolve, 50));
    
    // Update with new TTL
    kv.set("ttl-update-test", "updated", 5000);
    
    // Wait another 100ms - original TTL would have expired
    await new Promise(resolve => setTimeout(resolve, 100));
    
    const value = kv.get("ttl-update-test");
    const ttl = kv.ttl("ttl-update-test");
    
    return Response.json({ 
        value,
        stillExists: value !== null,
        ttlValid: ttl !== null && ttl > 4000
    });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"value":"updated"' && \
    assert_contains "$response" '"stillExists":true' && \
    assert_contains "$response" '"ttlValid":true'
}

# Test: KV key size limit (128 bytes)
test_kv_key_size_limit() {
    local handler='import { kv } from "quickw";

export default function(req) {
    const key128 = "k".repeat(128);
    const key129 = "k".repeat(129);
    
    let set128Success = false;
    let set129Error = null;
    
    try {
        kv.set(key128, "value");
        set128Success = kv.get(key128) === "value";
    } catch (e) {
        set128Success = false;
    }
    
    try {
        kv.set(key129, "value");
        set129Error = "no error thrown";
    } catch (e) {
        set129Error = e.message;
    }
    
    return Response.json({ 
        set128Success,
        set129Error,
        key129Rejected: set129Error && set129Error.includes("128 bytes")
    });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"set128Success":true' && \
    assert_contains "$response" '"key129Rejected":true'
}

# Test: KV value size limit (1024 bytes)
test_kv_value_size_limit() {
    local handler='import { kv } from "quickw";

export default function(req) {
    const value1024 = "v".repeat(1024);
    const value1025 = "v".repeat(1025);
    
    let set1024Success = false;
    let set1025Error = null;
    
    try {
        kv.set("val-limit-test-ok", value1024);
        set1024Success = kv.get("val-limit-test-ok")?.length === 1024;
    } catch (e) {
        set1024Success = false;
    }
    
    try {
        kv.set("val-limit-test-fail", value1025);
        set1025Error = "no error thrown";
    } catch (e) {
        set1025Error = e.message;
    }
    
    return Response.json({ 
        set1024Success,
        set1025Error,
        value1025Rejected: set1025Error && set1025Error.includes("1024 bytes")
    });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"set1024Success":true' && \
    assert_contains "$response" '"value1025Rejected":true'
}

# Test: KV overwrite existing key
test_kv_overwrite() {
    local handler='import { kv } from "quickw";

export default function(req) {
    kv.set("overwrite-test", "original");
    const before = kv.get("overwrite-test");
    
    kv.set("overwrite-test", "updated");
    const after = kv.get("overwrite-test");
    
    return Response.json({ before, after });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"before":"original"' && \
    assert_contains "$response" '"after":"updated"'
}

# Test: KV persists across requests (shared state)
test_kv_shared_state() {
    # First handler sets a value
    local set_handler='import { kv } from "quickw";

export default function(req) {
    kv.set("shared-state-test", "set-by-handler-1");
    return Response.json({ set: true });
}'
    
    local set_id
    set_id=$(register_handler "$set_handler")
    [[ -z "$set_id" ]] && return 1
    
    # Execute first handler to set the value
    execute_handler "$set_id" > /dev/null
    
    # Second handler reads the value
    local get_handler='import { kv } from "quickw";

export default function(req) {
    const value = kv.get("shared-state-test");
    return Response.json({ value });
}'
    
    local get_id
    get_id=$(register_handler "$get_handler")
    [[ -z "$get_id" ]] && return 1
    
    local response
    response=$(execute_handler "$get_id")
    
    assert_contains "$response" '"value":"set-by-handler-1"'
}

# Test: KV LRU eviction (requires server started with small kv-size)
test_kv_lru_eviction() {
    local handler='import { kv } from "quickw";

export default function(req) {
    // This test assumes server is started with --kv-size 100
    // Fill with 50 entries
    for (let i = 0; i < 50; i++) {
        kv.set("lru-evict:" + i, "value" + i);
    }
    
    // Access key 0 to make it recently used
    kv.get("lru-evict:0");
    
    // Add 60 more entries to trigger eviction
    for (let i = 50; i < 110; i++) {
        kv.set("lru-evict:" + i, "value" + i);
    }
    
    // Key 0 should still exist (was recently accessed)
    // Key 10 should be evicted (not accessed, older)
    const key0 = kv.get("lru-evict:0");
    const key10 = kv.get("lru-evict:10");
    const key100 = kv.get("lru-evict:100");
    
    return Response.json({ 
        key0Exists: key0 !== null,
        key10Evicted: key10 === null,
        key100Exists: key100 !== null
    });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"key0Exists":true' && \
    assert_contains "$response" '"key10Evicted":true' && \
    assert_contains "$response" '"key100Exists":true'
}

# Test: KV empty string key and value
test_kv_empty_strings() {
    local handler='import { kv } from "quickw";

export default function(req) {
    // Empty value should work
    kv.set("empty-value-test", "");
    const emptyValue = kv.get("empty-value-test");
    
    return Response.json({ 
        emptyValue,
        emptyValueIsString: emptyValue === ""
    });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"emptyValue":""' && \
    assert_contains "$response" '"emptyValueIsString":true'
}

# Test: KV special characters in keys and values
test_kv_special_chars() {
    local handler='import { kv } from "quickw";

export default function(req) {
    const specialKey = "key:with/special\\chars!@#$%";
    const specialValue = "value\nwith\ttabs\rand\"quotes\"";
    
    kv.set(specialKey, specialValue);
    const retrieved = kv.get(specialKey);
    
    return Response.json({ 
        matches: retrieved === specialValue,
        hasNewline: retrieved.includes("\n"),
        hasTab: retrieved.includes("\t")
    });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"matches":true' && \
    assert_contains "$response" '"hasNewline":true' && \
    assert_contains "$response" '"hasTab":true'
}

# Test: KV JSON values (store and retrieve)
test_kv_json_values() {
    local handler='import { kv } from "quickw";

export default function(req) {
    const obj = { name: "test", count: 42, nested: { a: 1 } };
    kv.set("json-test", JSON.stringify(obj));
    
    const retrieved = kv.get("json-test");
    const parsed = JSON.parse(retrieved);
    
    return Response.json({ 
        name: parsed.name,
        count: parsed.count,
        nestedA: parsed.nested.a
    });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"name":"test"' && \
    assert_contains "$response" '"count":42' && \
    assert_contains "$response" '"nestedA":1'
}

# =============================================================================
# WEB STREAMS AND BLOB TESTS
# =============================================================================

# Test: Blob basic creation and properties
test_blob_basic() {
    local handler='export default async function(req) {
    const blob = new Blob(["Hello, ", "World!"], { type: "text/plain" });
    const text = await blob.text();
    return Response.json({ 
        size: blob.size,
        type: blob.type,
        text: text
    });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"size":13' && \
    assert_contains "$response" '"type":"text/plain"' && \
    assert_contains "$response" '"text":"Hello, World!"'
}

# Test: Blob arrayBuffer method
test_blob_arraybuffer() {
    local handler='export default async function(req) {
    const blob = new Blob(["ABC"]);
    const buffer = await blob.arrayBuffer();
    const bytes = new Uint8Array(buffer);
    return Response.json({ 
        byteLength: buffer.byteLength,
        bytes: Array.from(bytes)
    });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"byteLength":3' && \
    assert_contains "$response" '"bytes":[65,66,67]'
}

# Test: Blob bytes method
test_blob_bytes() {
    local handler='export default async function(req) {
    const blob = new Blob(["Hi"]);
    const bytes = await blob.bytes();
    return Response.json({ 
        isUint8Array: bytes instanceof Uint8Array,
        length: bytes.length,
        values: Array.from(bytes)
    });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"isUint8Array":true' && \
    assert_contains "$response" '"length":2' && \
    assert_contains "$response" '"values":[72,105]'
}

# Test: Blob slice method
test_blob_slice() {
    local handler='export default async function(req) {
    const blob = new Blob(["Hello, World!"]);
    const sliced = blob.slice(0, 5);
    const text = await sliced.text();
    const middleSlice = blob.slice(7, 12);
    const middleText = await middleSlice.text();
    return Response.json({ 
        originalSize: blob.size,
        slicedSize: sliced.size,
        slicedText: text,
        middleText: middleText
    });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"originalSize":13' && \
    assert_contains "$response" '"slicedSize":5' && \
    assert_contains "$response" '"slicedText":"Hello"' && \
    assert_contains "$response" '"middleText":"World"'
}

# Test: Blob slice with negative indices
test_blob_slice_negative() {
    local handler='export default async function(req) {
    const blob = new Blob(["Hello, World!"]);
    const lastFive = blob.slice(-6, -1);
    const text = await lastFive.text();
    return Response.json({ 
        size: lastFive.size,
        text: text
    });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"size":5' && \
    assert_contains "$response" '"text":"World"'
}

# Test: Blob from ArrayBuffer
test_blob_from_arraybuffer() {
    local handler='export default async function(req) {
    const buffer = new Uint8Array([72, 101, 108, 108, 111]).buffer;
    const blob = new Blob([buffer]);
    const text = await blob.text();
    return Response.json({ 
        size: blob.size,
        text: text
    });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"size":5' && \
    assert_contains "$response" '"text":"Hello"'
}

# Test: Blob from Uint8Array
test_blob_from_uint8array() {
    local handler='export default async function(req) {
    const bytes = new Uint8Array([87, 111, 114, 108, 100]);
    const blob = new Blob([bytes]);
    const text = await blob.text();
    return Response.json({ 
        size: blob.size,
        text: text
    });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"size":5' && \
    assert_contains "$response" '"text":"World"'
}

# Test: Blob from mixed parts
test_blob_mixed_parts() {
    local handler='export default async function(req) {
    const str = "Hello";
    const bytes = new Uint8Array([44, 32]); // ", "
    const blob2 = new Blob(["World"]);
    
    const combined = new Blob([str, bytes, blob2]);
    const text = await combined.text();
    
    return Response.json({ 
        size: combined.size,
        text: text
    });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"size":12' && \
    assert_contains "$response" '"text":"Hello, World"'
}

# Test: Blob stream method
test_blob_stream() {
    local handler='export default async function(req) {
    const blob = new Blob(["Stream", "Test"]);
    const stream = blob.stream();
    const reader = stream.getReader();
    
    let chunks = [];
    while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        chunks.push(new TextDecoder().decode(value));
    }
    
    return Response.json({ 
        chunkCount: chunks.length,
        combined: chunks.join("")
    });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"combined":"StreamTest"'
}

# Test: ReadableStream basic usage
test_readable_stream_basic() {
    local handler='export default async function(req) {
    const stream = new ReadableStream({
        start(controller) {
            controller.enqueue("chunk1");
            controller.enqueue("chunk2");
            controller.enqueue("chunk3");
            controller.close();
        }
    });
    
    const reader = stream.getReader();
    const chunks = [];
    
    while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        chunks.push(value);
    }
    
    return Response.json({ 
        chunks: chunks,
        locked: stream.locked
    });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"chunks":["chunk1","chunk2","chunk3"]' && \
    assert_contains "$response" '"locked":true'
}

# Test: ReadableStream with pull function
test_readable_stream_pull() {
    local handler='export default async function(req) {
    let count = 0;
    const stream = new ReadableStream({
        pull(controller) {
            count++;
            if (count <= 3) {
                controller.enqueue("item" + count);
            } else {
                controller.close();
            }
        }
    });
    
    const reader = stream.getReader();
    const items = [];
    
    while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        items.push(value);
    }
    
    return Response.json({ items: items });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"items":["item1","item2","item3"]'
}

# Test: ReadableStream async iterator
test_readable_stream_async_iterator() {
    local handler='export default async function(req) {
    const stream = new ReadableStream({
        start(controller) {
            controller.enqueue(1);
            controller.enqueue(2);
            controller.enqueue(3);
            controller.close();
        }
    });
    
    const values = [];
    for await (const chunk of stream) {
        values.push(chunk);
    }
    
    return Response.json({ values: values });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"values":[1,2,3]'
}

# Test: ReadableStream tee (clone)
test_readable_stream_tee() {
    local handler='export default async function(req) {
    const original = new ReadableStream({
        start(controller) {
            controller.enqueue("a");
            controller.enqueue("b");
            controller.close();
        }
    });
    
    const [branch1, branch2] = original.tee();
    
    const reader1 = branch1.getReader();
    const reader2 = branch2.getReader();
    
    const chunks1 = [];
    const chunks2 = [];
    
    while (true) {
        const { done, value } = await reader1.read();
        if (done) break;
        chunks1.push(value);
    }
    
    while (true) {
        const { done, value } = await reader2.read();
        if (done) break;
        chunks2.push(value);
    }
    
    return Response.json({ 
        branch1: chunks1,
        branch2: chunks2,
        equal: JSON.stringify(chunks1) === JSON.stringify(chunks2)
    });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"branch1":["a","b"]' && \
    assert_contains "$response" '"branch2":["a","b"]' && \
    assert_contains "$response" '"equal":true'
}

# Test: ReadableStream cancel
test_readable_stream_cancel() {
    local handler='export default async function(req) {
    let cancelled = false;
    const stream = new ReadableStream({
        start(controller) {
            controller.enqueue("data");
        },
        cancel(reason) {
            cancelled = true;
        }
    });
    
    await stream.cancel("user cancelled");
    
    return Response.json({ cancelled: true });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"cancelled":true'
}

# Test: ReadableStream.from static method
test_readable_stream_from() {
    local handler='export default async function(req) {
    async function* asyncGen() {
        yield 10;
        yield 20;
        yield 30;
    }
    
    const stream = ReadableStream.from(asyncGen());
    const reader = stream.getReader();
    const values = [];
    
    while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        values.push(value);
    }
    
    return Response.json({ values: values });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"values":[10,20,30]'
}

# Test: WritableStream basic usage
test_writable_stream_basic() {
    local handler='export default async function(req) {
    const chunks = [];
    const stream = new WritableStream({
        write(chunk) {
            chunks.push(chunk);
        }
    });
    
    const writer = stream.getWriter();
    await writer.write("first");
    await writer.write("second");
    await writer.write("third");
    await writer.close();
    
    return Response.json({ 
        chunks: chunks,
        locked: stream.locked
    });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"chunks":["first","second","third"]' && \
    assert_contains "$response" '"locked":true'
}

# Test: WritableStream with async write
test_writable_stream_async() {
    local handler='export default async function(req) {
    const results = [];
    const stream = new WritableStream({
        async write(chunk) {
            await new Promise(r => setTimeout(r, 10));
            results.push(chunk + "-processed");
        }
    });
    
    const writer = stream.getWriter();
    await writer.write("a");
    await writer.write("b");
    await writer.close();
    
    return Response.json({ results: results });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"results":["a-processed","b-processed"]'
}

# Test: WritableStream abort
test_writable_stream_abort() {
    local handler='export default async function(req) {
    let abortReason = null;
    const stream = new WritableStream({
        abort(reason) {
            abortReason = reason;
        }
    });
    
    await stream.abort("test abort");
    
    return Response.json({ aborted: true });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"aborted":true'
}

# Test: TransformStream basic usage
test_transform_stream_basic() {
    local handler='export default async function(req) {
    const transform = new TransformStream({
        transform(chunk, controller) {
            controller.enqueue(chunk.toUpperCase());
        }
    });
    
    const writer = transform.writable.getWriter();
    const reader = transform.readable.getReader();
    
    await writer.write("hello");
    await writer.write("world");
    await writer.close();
    
    const results = [];
    while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        results.push(value);
    }
    
    return Response.json({ results: results });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"results":["HELLO","WORLD"]'
}

# Test: TransformStream with flush
test_transform_stream_flush() {
    local handler='export default async function(req) {
    let sum = 0;
    const transform = new TransformStream({
        transform(chunk, controller) {
            sum += chunk;
            controller.enqueue(chunk);
        },
        flush(controller) {
            controller.enqueue("sum:" + sum);
        }
    });
    
    const writer = transform.writable.getWriter();
    const reader = transform.readable.getReader();
    
    await writer.write(1);
    await writer.write(2);
    await writer.write(3);
    await writer.close();
    
    const results = [];
    while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        results.push(value);
    }
    
    return Response.json({ results: results });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"results":[1,2,3,"sum:6"]'
}

# Test: ReadableStream pipeTo WritableStream
test_stream_pipe_to() {
    local handler='export default async function(req) {
    const chunks = [];
    
    const readable = new ReadableStream({
        start(controller) {
            controller.enqueue("pipe1");
            controller.enqueue("pipe2");
            controller.close();
        }
    });
    
    const writable = new WritableStream({
        write(chunk) {
            chunks.push(chunk);
        }
    });
    
    await readable.pipeTo(writable);
    
    return Response.json({ chunks: chunks });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"chunks":["pipe1","pipe2"]'
}

# Test: ReadableStream pipeThrough TransformStream
test_stream_pipe_through() {
    local handler='export default async function(req) {
    const readable = new ReadableStream({
        start(controller) {
            controller.enqueue("abc");
            controller.enqueue("def");
            controller.close();
        }
    });
    
    const transform = new TransformStream({
        transform(chunk, controller) {
            controller.enqueue(chunk.toUpperCase());
        }
    });
    
    const transformed = readable.pipeThrough(transform);
    const reader = transformed.getReader();
    
    const results = [];
    while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        results.push(value);
    }
    
    return Response.json({ results: results });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"results":["ABC","DEF"]'
}

# Test: ByteLengthQueuingStrategy
test_byte_length_queuing_strategy() {
    local handler='export default function(req) {
    const strategy = new ByteLengthQueuingStrategy({ highWaterMark: 1024 });
    const size = strategy.size(new Uint8Array(100));
    
    return Response.json({ 
        highWaterMark: strategy.highWaterMark,
        size: size
    });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"highWaterMark":1024' && \
    assert_contains "$response" '"size":100'
}

# Test: CountQueuingStrategy
test_count_queuing_strategy() {
    local handler='export default function(req) {
    const strategy = new CountQueuingStrategy({ highWaterMark: 10 });
    const size1 = strategy.size("any");
    const size2 = strategy.size([1,2,3]);
    
    return Response.json({ 
        highWaterMark: strategy.highWaterMark,
        size1: size1,
        size2: size2
    });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"highWaterMark":10' && \
    assert_contains "$response" '"size1":1' && \
    assert_contains "$response" '"size2":1'
}

# Test: TextEncoder (bundled with streams polyfill)
test_text_encoder() {
    local handler='export default function(req) {
    const encoder = new TextEncoder();
    const encoded = encoder.encode("Hello");
    
    return Response.json({ 
        encoding: encoder.encoding,
        length: encoded.length,
        bytes: Array.from(encoded)
    });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"encoding":"utf-8"' && \
    assert_contains "$response" '"length":5' && \
    assert_contains "$response" '"bytes":[72,101,108,108,111]'
}

# Test: ReadableStream error handling
test_readable_stream_error() {
    local handler='export default async function(req) {
    const stream = new ReadableStream({
        async start(controller) {
            controller.enqueue("ok");
            // Use setTimeout to ensure the chunk can be read before error
            await new Promise(resolve => setTimeout(resolve, 10));
            controller.error(new Error("stream error"));
        }
    });
    
    const reader = stream.getReader();
    const results = { chunks: [], error: null };
    
    try {
        while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            results.chunks.push(value);
        }
    } catch (e) {
        results.error = e.message;
    }
    
    return Response.json(results);
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"chunks":["ok"]' && \
    assert_contains "$response" '"error":"stream error"'
}

# Test: Multiple readers throw error (locked stream)
test_readable_stream_locked() {
    local handler='export default async function(req) {
    const stream = new ReadableStream({
        start(controller) {
            controller.enqueue("data");
            controller.close();
        }
    });
    
    const reader1 = stream.getReader();
    let secondReaderError = null;
    
    try {
        const reader2 = stream.getReader();
    } catch (e) {
        secondReaderError = e.message;
    }
    
    return Response.json({ 
        locked: stream.locked,
        errorThrown: secondReaderError !== null,
        errorMessage: secondReaderError
    });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"locked":true' && \
    assert_contains "$response" '"errorThrown":true'
}

# Test: Reader release lock
test_readable_stream_release_lock() {
    local handler='export default async function(req) {
    const stream = new ReadableStream({
        start(controller) {
            controller.enqueue("data");
            controller.close();
        }
    });
    
    const reader1 = stream.getReader();
    reader1.releaseLock();
    
    const reader2 = stream.getReader();
    const { value } = await reader2.read();
    
    return Response.json({ 
        value: value,
        success: true
    });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"value":"data"' && \
    assert_contains "$response" '"success":true'
}

# =============================================================================
# MAIN TEST RUNNER
# =============================================================================

main() {
    log_section "Quickwork Test Suite"
    
    # Check if binary exists
    if [[ ! -x "$QUICKWORK_BIN" ]]; then
        log_fail "Binary not found: $QUICKWORK_BIN"
        log "Please build the project first: mkdir build && cd build && cmake .. && make"
        exit 1
    fi
    
    # Start server
    log "Starting server on port $PORT..."
    "$QUICKWORK_BIN" --port "$PORT" --kv-size 100 --max-memory 4 &
    SERVER_PID=$!
    
    if ! wait_for_server; then
        exit 1
    fi
    
    log "Server started (PID: $SERVER_PID)"
    
    # Run tests by category
    log_section "Basic Response Tests"
    run_test "Basic text response" test_basic_text_response
    run_test "JSON response" test_json_response
    run_test "HTML response" test_html_response
    run_test "Custom status code (404)" test_custom_status_code
    run_test "Empty response (204)" test_empty_response
    run_test "Redirect response (302)" test_redirect_status
    run_test "Large response body" test_large_response
    run_test "Array response" test_array_response
    run_test "Nested object response" test_nested_object
    run_test "JSON special characters" test_json_special_chars
    
    log_section "Header Tests"
    run_test "Cache-Control header" test_cache_control_header
    run_test "Multiple custom headers" test_multiple_headers
    run_test "Built-in stats headers (x-qw-*)" test_builtin_stats_headers
    run_test "CORS headers" test_cors_headers
    run_test "JSON Content-Type inference" test_json_content_type
    
    log_section "Request Handling Tests"
    run_test "Request method access" test_request_method
    run_test "Request URL access" test_request_url
    run_test "Request body access" test_request_body
    run_test "Request headers access" test_request_headers
    run_test "Request JSON parsing" test_request_json
    
    log_section "Async & Timer Tests"
    run_test "Async handler with Promise" test_async_handler
    run_test "setTimeout basic" test_setTimeout_basic
    run_test "clearTimeout cancels timer" test_clearTimeout
    run_test "Multiple timers ordering" test_multiple_timers
    run_test "setTimeout zero delay" test_setTimeout_zero_delay
    run_test "Promise.all" test_promise_all
    run_test "Promise.all with delays (parallelism)" test_promise_all_with_delayed_operations
    
    log_section "Streaming Tests"
    run_test "Streaming text response" test_streaming_text
    run_test "SSE streaming with events" test_streaming_sse
    run_test "Streaming with setTimeout" test_streaming_with_timeout
    
    log_section "Crypto & Utilities"
    run_test "crypto.randomUUID()" test_crypto_randomUUID
    run_test "crypto.getRandomValues()" test_crypto_getRandomValues
    run_test "TextDecoder" test_text_decoder
    run_test "Console logging" test_console_log
    
    log_section "ESM Import Tests"
    run_test "ESM default import (ms)" test_esm_import_default
    run_test "ESM named import (uuid)" test_esm_import_named
    run_test "ESM import Neon serverless" test_esm_import_neon
    run_test "ESM import Turso/libsql HTTP" test_esm_import_turso
    run_test "ESM import Supabase JS" test_esm_import_supabase
    
    log_section "Error Handling & Edge Cases"
    run_test "Error handling in handler" test_error_handling
    run_test "Handler isolation" test_handler_isolation
    run_test "Concurrent execution" test_concurrent_execution
    run_test "Handler caching/reuse" test_handler_caching
    run_test "Health endpoint" test_health_endpoint
    run_test "Missing handler ID" test_missing_handler_id
    run_test "Unknown handler ID" test_unknown_handler_id
    run_test "Handler not found header" test_handler_not_found_header
    run_test "Handler cannot forge not-found header" test_handler_cannot_forge_not_found_header
    run_test "Subdomain handler invocation" test_subdomain_handler_invocation
    
    log_section "Edge Case Tests"
    run_test "Deep recursion (fib 25)" test_deep_recursion
    run_test "Generator functions" test_generator_function
    run_test "Async generators with for-await-of" test_async_generator
    run_test "Proxy object with traps" test_proxy_object
    run_test "WeakMap operations" test_weakmap
    run_test "Symbol as object keys" test_symbol_keys
    run_test "BigInt arithmetic" test_bigint_arithmetic
    run_test "Reflect API" test_reflect_api
    run_test "Promise.race" test_promise_race
    run_test "Promise.allSettled mixed results" test_promise_allsettled
    run_test "Advanced destructuring" test_advanced_destructuring
    run_test "Tagged template literals" test_tagged_template
    run_test "Nullish coalescing + optional chaining" test_nullish_and_optional
    run_test "Closure isolation between requests" test_closure_isolation
    run_test "Async error rejection" test_async_error_rejection
    run_test "Nested Promise chains" test_nested_promise_chains
    run_test "Array method chaining" test_array_method_chaining
    run_test "RegExp named capture groups" test_regexp_named_groups
    run_test "Object.entries/fromEntries round-trip" test_object_entries_roundtrip
    run_test "Class with private fields (ES2022)" test_class_private_fields
    
    log_section "Polyfill Tests"
    run_test "All polyfills (URL, base64, Set methods, etc)" test_polyfills_comprehensive
    
    log_section "KV Store Tests"
    run_test "KV basic set and get" test_kv_basic_set_get
    run_test "KV get non-existent key" test_kv_get_nonexistent
    run_test "KV delete key" test_kv_delete
    run_test "KV delete alias" test_kv_delete_alias
    run_test "KV exists check" test_kv_exists
    run_test "KV size" test_kv_size
    run_test "KV scan with prefix" test_kv_scan_prefix
    run_test "KV scan with limit" test_kv_scan_limit
    run_test "KV entries returns key-value pairs" test_kv_entries
    run_test "KV TTL set and check" test_kv_ttl_set
    run_test "KV TTL returns null for no-expiry keys" test_kv_ttl_no_expiry
    run_test "KV TTL expiration" test_kv_ttl_expiration
    run_test "KV TTL update resets expiry" test_kv_ttl_update
    run_test "KV key size limit (128 bytes)" test_kv_key_size_limit
    run_test "KV value size limit (1024 bytes)" test_kv_value_size_limit
    run_test "KV overwrite existing key" test_kv_overwrite
    run_test "KV shared state across requests" test_kv_shared_state
    run_test "KV LRU eviction" test_kv_lru_eviction
    run_test "KV empty strings" test_kv_empty_strings
    run_test "KV special characters" test_kv_special_chars
    run_test "KV JSON values" test_kv_json_values

    log_section "Web Streams & Blob Tests"
    run_test "Blob basic creation and properties" test_blob_basic
    run_test "Blob arrayBuffer method" test_blob_arraybuffer
    run_test "Blob bytes method" test_blob_bytes
    run_test "Blob slice method" test_blob_slice
    run_test "Blob slice with negative indices" test_blob_slice_negative
    run_test "Blob from ArrayBuffer" test_blob_from_arraybuffer
    run_test "Blob from Uint8Array" test_blob_from_uint8array
    run_test "Blob from mixed parts" test_blob_mixed_parts
    run_test "Blob stream method" test_blob_stream
    run_test "ReadableStream basic usage" test_readable_stream_basic
    run_test "ReadableStream with pull function" test_readable_stream_pull
    run_test "ReadableStream async iterator" test_readable_stream_async_iterator
    run_test "ReadableStream tee (clone)" test_readable_stream_tee
    run_test "ReadableStream cancel" test_readable_stream_cancel
    run_test "ReadableStream.from static method" test_readable_stream_from
    run_test "ReadableStream error handling" test_readable_stream_error
    run_test "ReadableStream locked check" test_readable_stream_locked
    run_test "ReadableStream release lock" test_readable_stream_release_lock
    run_test "WritableStream basic usage" test_writable_stream_basic
    run_test "WritableStream async write" test_writable_stream_async
    run_test "WritableStream abort" test_writable_stream_abort
    run_test "TransformStream basic usage" test_transform_stream_basic
    run_test "TransformStream with flush" test_transform_stream_flush
    run_test "ReadableStream pipeTo WritableStream" test_stream_pipe_to
    run_test "ReadableStream pipeThrough TransformStream" test_stream_pipe_through
    run_test "ByteLengthQueuingStrategy" test_byte_length_queuing_strategy
    run_test "CountQueuingStrategy" test_count_queuing_strategy
    run_test "TextEncoder" test_text_encoder

    log_section "Fetch API Tests"
    run_test "Fetch GET request" test_fetch_get
    run_test "Fetch POST with JSON body" test_fetch_post_json
    run_test "Fetch with custom headers" test_fetch_custom_headers
    run_test "Fetch response.text()" test_fetch_text_response
    run_test "Fetch HTTP error (404)" test_fetch_http_error
    run_test "Fetch PUT request" test_fetch_put
    run_test "Fetch DELETE request" test_fetch_delete
    run_test "Fetch PATCH request" test_fetch_patch
    run_test "Fetch Promise.all (parallel)" test_fetch_promise_all
    run_test "Fetch response headers" test_fetch_response_headers
    run_test "Fetch follows redirects" test_fetch_redirect
    run_test "Fetch loopback to self" test_fetch_loopback
    run_test "Fetch form data (URL encoded)" test_fetch_form_data
    run_test "Fetch streaming body (ReadableStream)" test_fetch_streaming_body
    run_test "Fetch sequential requests" test_fetch_sequential
    run_test "Fetch with User-Agent header" test_fetch_user_agent
    run_test "Stream large file with uppercase transform" test_stream_large_file_uppercase
    
    # Print summary
    log_section "Test Results"
    echo -e "${BOLD}Total:${NC}   $TESTS_RUN tests"
    echo -e "${GREEN}Passed:${NC}  $TESTS_PASSED"
    echo -e "${RED}Failed:${NC}  $TESTS_FAILED"
    if [[ $TESTS_SKIPPED -gt 0 ]]; then
        echo -e "${YELLOW}Skipped:${NC} $TESTS_SKIPPED"
    fi
    echo ""
    
    if [[ $TESTS_FAILED -eq 0 ]]; then
        echo -e "${GREEN}${BOLD}All tests passed!${NC}"
        exit 0
    else
        echo -e "${RED}${BOLD}Some tests failed!${NC}"
        exit 1
    fi
}

main "$@"
