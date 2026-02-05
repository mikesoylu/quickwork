# =============================================================================
# STREAMING TESTS
# =============================================================================

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

# Test: Streaming concurrency - multiple streaming requests should run concurrently
# This test verifies that streaming handlers don't block each other, even with -j 1
# Uses the single-threaded server (PORT_SINGLE) to prove async concurrency on one thread
test_streaming_concurrency() {
    # Handler that takes 1 second total (3 events with 333ms delays)
    local handler='export default async function(req) {
        const stream = new StreamResponse();
        
        function pause(ms) {
            return new Promise(resolve => setTimeout(resolve, ms));
        }
        
        for (let i = 1; i <= 3; i++) {
            stream.write("data: Event " + i + "\n\n");
            await pause(333);
        }
        
        stream.close();
        return stream;
    }'
    
    # Register handler on the SINGLE-THREADED server
    local id
    id=$(curl -s -X POST "${BASE_URL_SINGLE}" \
        -H "Content-Type: application/javascript" \
        -d "$handler" | grep -o '"id":"[^"]*"' | cut -d'"' -f4)
    [[ -z "$id" ]] && return 1
    
    # Send 5 concurrent requests to the SINGLE-THREADED server
    # Each request takes ~1 second
    # If concurrent (async on single thread): should complete in ~1-2 seconds
    # If sequential (blocking): would take ~5 seconds
    local start_ms end_ms elapsed_ms
    start_ms=$(python3 -c 'import time; print(int(time.time() * 1000))' 2>/dev/null || date +%s%3N)
    
    local pids=()
    for i in 1 2 3 4 5; do
        curl -s -H "x-handler-id: $id" "${BASE_URL_SINGLE}/" > /dev/null &
        pids+=($!)
    done
    
    # Wait for all requests to complete
    for pid in "${pids[@]}"; do
        wait "$pid"
    done
    
    end_ms=$(python3 -c 'import time; print(int(time.time() * 1000))' 2>/dev/null || date +%s%3N)
    elapsed_ms=$((end_ms - start_ms))
    
    log_debug "Streaming concurrency test (-j 1): 5 requests completed in ${elapsed_ms}ms"
    
    # Should complete in under 2500ms if running concurrently on the single thread
    # (each request is ~1000ms, sequential would be ~5000ms)
    [[ $elapsed_ms -lt 2500 ]]
}
