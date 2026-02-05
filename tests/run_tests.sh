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

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=run_tests.d/common.sh
source "${SCRIPT_DIR}/common.sh"
# shellcheck source=run_tests.d/tests_basic.sh
source "${SCRIPT_DIR}/tests_basic.sh"
# shellcheck source=run_tests.d/tests_headers.sh
source "${SCRIPT_DIR}/tests_headers.sh"
# shellcheck source=run_tests.d/tests_request.sh
source "${SCRIPT_DIR}/tests_request.sh"
# shellcheck source=run_tests.d/tests_async.sh
source "${SCRIPT_DIR}/tests_async.sh"
# shellcheck source=run_tests.d/tests_streaming.sh
source "${SCRIPT_DIR}/tests_streaming.sh"
# shellcheck source=run_tests.d/tests_crypto_utils.sh
source "${SCRIPT_DIR}/tests_crypto_utils.sh"
# shellcheck source=run_tests.d/tests_esm_imports.sh
source "${SCRIPT_DIR}/tests_esm_imports.sh"
# shellcheck source=run_tests.d/tests_error_edge.sh
source "${SCRIPT_DIR}/tests_error_edge.sh"
# shellcheck source=run_tests.d/tests_edge_cases.sh
source "${SCRIPT_DIR}/tests_edge_cases.sh"
# shellcheck source=run_tests.d/tests_polyfills.sh
source "${SCRIPT_DIR}/tests_polyfills.sh"
# shellcheck source=run_tests.d/tests_kv_store.sh
source "${SCRIPT_DIR}/tests_kv_store.sh"
# shellcheck source=run_tests.d/tests_web_streams_blob.sh
source "${SCRIPT_DIR}/tests_web_streams_blob.sh"
# shellcheck source=run_tests.d/tests_fetch_api.sh
source "${SCRIPT_DIR}/tests_fetch_api.sh"

# =============================================================================
# MAIN TEST RUNNER
# =============================================================================

main() {
    parse_args "$@"

    log_section "Quickwork Test Suite"
    
    # Check if binary exists
    if [[ ! -x "$QUICKWORK_BIN" ]]; then
        log_fail "Binary not found: $QUICKWORK_BIN"
        log "Please build the project first: mkdir build && cd build && cmake .. && make"
        exit 1
    fi
    
    # Start main server with multiple threads (-j 8)
    log "Starting main server on port $PORT with -j 8..."
    "$QUICKWORK_BIN" --port "$PORT" --kv-size 100 --max-memory 4 -j 8 &
    SERVER_PID=$!
    
    if ! wait_for_server "$BASE_URL"; then
        exit 1
    fi
    
    log "Main server started (PID: $SERVER_PID)"
    
    # Start single-threaded server (-j 1) for concurrency tests
    log "Starting single-threaded server on port $PORT_SINGLE with -j 1..."
    "$QUICKWORK_BIN" --port "$PORT_SINGLE" --kv-size 100 --max-memory 4 -j 1 &
    SERVER_SINGLE_PID=$!
    
    if ! wait_for_server "$BASE_URL_SINGLE"; then
        exit 1
    fi
    
    log "Single-threaded server started (PID: $SERVER_SINGLE_PID)"
    
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
    run_test "Streaming concurrency (-j 1, 5 parallel requests)" test_streaming_concurrency
    
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
    run_test "ESM import memfs (Node.js polyfills)" test_esm_import_memfs
    
    log_section "Error Handling & Edge Cases"
    run_test "Error handling in handler" test_error_handling
    run_test "CPU timeout kills infinite loop" test_cpu_timeout_infinite_loop
    run_test "CPU timeout allows setTimeout" test_cpu_timeout_allows_settimeout
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
