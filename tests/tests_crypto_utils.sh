# =============================================================================
# CRYPTO & UTILITIES
# =============================================================================

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
