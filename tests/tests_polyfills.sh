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
