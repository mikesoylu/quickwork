# =============================================================================
# HEADER TESTS
# =============================================================================

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
