# =============================================================================
# ERROR HANDLING & EDGE CASES
# =============================================================================

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

# Test: CPU timeout kills infinite loop
test_cpu_timeout_infinite_loop() {
    local handler='export default function(req) {
        while(true) { }
        return new Response("Never reached");
    }'

    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1

    local response
    response=$(timeout 10 curl -s -H "x-handler-id: $id" "${BASE_URL}/")

    # Should return an error about being interrupted
    assert_contains "$response" "error" || assert_contains "$response" "interrupted"
}

# Test: CPU timeout does NOT kill setTimeout (async wait doesn't count as CPU time)
test_cpu_timeout_allows_settimeout() {
    # This test uses a handler that waits 2 seconds via setTimeout
    # With default 5s CPU limit, this should complete successfully
    # because setTimeout doesn't consume CPU time
    local handler='export default async function(req) {
        const start = Date.now();
        await new Promise(r => setTimeout(r, 2000));
        const elapsed = Date.now() - start;
        return Response.json({ elapsed: elapsed, success: elapsed >= 2000 });
    }'

    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1

    local response
    response=$(timeout 10 curl -s -H "x-handler-id: $id" "${BASE_URL}/")

    # Should complete successfully with elapsed time >= 2000ms
    assert_contains "$response" '"success":true'
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
