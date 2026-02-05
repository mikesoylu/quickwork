# =============================================================================
# ASYNC & TIMER TESTS
# =============================================================================

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
