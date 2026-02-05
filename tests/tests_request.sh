# =============================================================================
# REQUEST HANDLING TESTS
# =============================================================================

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
