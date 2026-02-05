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
