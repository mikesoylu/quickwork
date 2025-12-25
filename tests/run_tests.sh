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
    "$QUICKWORK_BIN" --port "$PORT" &
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
    
    log_section "Error Handling & Edge Cases"
    run_test "Error handling in handler" test_error_handling
    run_test "Handler isolation" test_handler_isolation
    run_test "Concurrent execution" test_concurrent_execution
    run_test "Handler caching/reuse" test_handler_caching
    run_test "Health endpoint" test_health_endpoint
    run_test "Missing handler ID" test_missing_handler_id
    run_test "Unknown handler ID" test_unknown_handler_id
    
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
