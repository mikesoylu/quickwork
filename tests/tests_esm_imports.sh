# =============================================================================
# ESM IMPORT TESTS
# =============================================================================

# Test: ESM default import (requires network - skip if no connection)
test_esm_import_default() {
    # Check network connectivity first
    if ! curl -s --connect-timeout 2 "https://esm.sh" > /dev/null 2>&1; then
        log_debug "Skipping ESM test - no network connectivity"
        ((TESTS_SKIPPED++))
        return 0
    fi
    
    local handler='import ms from "https://esm.sh/ms@2.1.3";

export default function(req) {
    const result = ms("1h");
    return Response.json({ hours: result });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"hours":3600000'
}

# Test: ESM named import
test_esm_import_named() {
    # Check network connectivity first
    if ! curl -s --connect-timeout 2 "https://esm.sh" > /dev/null 2>&1; then
        log_debug "Skipping ESM test - no network connectivity"
        ((TESTS_SKIPPED++))
        return 0
    fi
    
    local handler='import { v4 as uuidv4 } from "https://esm.sh/uuid@9.0.0";

export default function(req) {
    const id = uuidv4();
    const valid = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(id);
    return Response.json({ valid: valid });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"valid":true'
}

# Test: ESM import Neon serverless postgres client
test_esm_import_neon() {
    # Check network connectivity first
    if ! curl -s --connect-timeout 2 "https://esm.sh" > /dev/null 2>&1; then
        log_debug "Skipping ESM test - no network connectivity"
        ((TESTS_SKIPPED++))
        return 0
    fi
    
    local handler='import { neon } from "https://esm.sh/@neondatabase/serverless";

export default function(req) {
    // Just verify the import works and neon is a function
    return Response.json({ 
        imported: true,
        isFunction: typeof neon === "function"
    });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"imported":true' && \
    assert_contains "$response" '"isFunction":true'
}

# Test: ESM import Turso/libsql HTTP client
test_esm_import_turso() {
    # Check network connectivity first
    if ! curl -s --connect-timeout 2 "https://esm.sh" > /dev/null 2>&1; then
        log_debug "Skipping ESM test - no network connectivity"
        ((TESTS_SKIPPED++))
        return 0
    fi
    
    local handler='import { createClient } from "https://esm.sh/@libsql/client/http";

export default function(req) {
    // Just verify the import works and createClient is a function
    return Response.json({ 
        imported: true,
        isFunction: typeof createClient === "function"
    });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"imported":true' && \
    assert_contains "$response" '"isFunction":true'
}

# Test: ESM import Supabase JS client
test_esm_import_supabase() {
    # Check network connectivity first
    if ! curl -s --connect-timeout 2 "https://esm.sh" > /dev/null 2>&1; then
        log_debug "Skipping ESM test - no network connectivity"
        ((TESTS_SKIPPED++))
        return 0
    fi
    
    local handler='import { createClient } from "https://esm.sh/@supabase/supabase-js";

export default function(req) {
    // Just verify the import works and createClient is a function
    return Response.json({ 
        imported: true,
        isFunction: typeof createClient === "function"
    });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"imported":true' && \
    assert_contains "$response" '"isFunction":true'
}

# Test: ESM import memfs (in-memory filesystem with Node.js polyfills)
test_esm_import_memfs() {
    # Check network connectivity first
    if ! curl -s --connect-timeout 2 "https://esm.sh" > /dev/null 2>&1; then
        log_debug "Skipping ESM test - no network connectivity"
        ((TESTS_SKIPPED++))
        return 0
    fi
    
    local handler='import memfs from "https://esm.sh/memfs";

export default function(req) {
    // Test that memfs loaded and has expected exports
    const hasFs = "fs" in memfs;
    const hasVolume = "Volume" in memfs;
    
    // Test basic file operations using the default fs
    const exists1 = memfs.fs.existsSync("/nonexistent.txt");
    
    return Response.json({ 
        imported: true,
        hasFs: hasFs,
        hasVolume: hasVolume,
        existsCheck: exists1 === false
    });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"imported":true' && \
    assert_contains "$response" '"hasFs":true' && \
    assert_contains "$response" '"hasVolume":true' && \
    assert_contains "$response" '"existsCheck":true'
}
