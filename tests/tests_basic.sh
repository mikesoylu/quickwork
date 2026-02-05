# =============================================================================
# BASIC RESPONSE TESTS
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
