# =============================================================================
# KV STORE TESTS
# =============================================================================

# Test: KV basic set and get
test_kv_basic_set_get() {
    local handler='import { kv } from "quickw";

export default function(req) {
    kv.set("test-key", "test-value");
    const value = kv.get("test-key");
    return Response.json({ value: value });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"value":"test-value"'
}

# Test: KV get non-existent key returns null
test_kv_get_nonexistent() {
    local handler='import { kv } from "quickw";

export default function(req) {
    const value = kv.get("nonexistent-key-12345");
    return Response.json({ value: value, isNull: value === null });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"value":null' && \
    assert_contains "$response" '"isNull":true'
}

# Test: KV delete key
test_kv_delete() {
    local handler='import { kv } from "quickw";

export default function(req) {
    kv.set("delete-test", "to-be-deleted");
    const before = kv.get("delete-test");
    const deleted = kv.del("delete-test");
    const after = kv.get("delete-test");
    return Response.json({ before, deleted, after });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"before":"to-be-deleted"' && \
    assert_contains "$response" '"deleted":true' && \
    assert_contains "$response" '"after":null'
}

# Test: KV delete alias works
test_kv_delete_alias() {
    local handler='import { kv } from "quickw";

export default function(req) {
    kv.set("delete-alias-test", "value");
    const deleted = kv.delete("delete-alias-test");
    const after = kv.get("delete-alias-test");
    return Response.json({ deleted, after });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"deleted":true' && \
    assert_contains "$response" '"after":null'
}

# Test: KV exists check
test_kv_exists() {
    local handler='import { kv } from "quickw";

export default function(req) {
    kv.set("exists-test", "value");
    const exists = kv.exists("exists-test");
    const notExists = kv.exists("nonexistent-exists-test");
    return Response.json({ exists, notExists });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"exists":true' && \
    assert_contains "$response" '"notExists":false'
}

# Test: KV size
test_kv_size() {
    local handler='import { kv } from "quickw";

export default function(req) {
    const initialSize = kv.size();
    kv.set("size-test-1", "a");
    kv.set("size-test-2", "b");
    kv.set("size-test-3", "c");
    const afterSet = kv.size();
    const increased = afterSet >= initialSize + 3;
    return Response.json({ initialSize, afterSet, increased });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"increased":true'
}

# Test: KV scan with prefix
test_kv_scan_prefix() {
    local handler='import { kv } from "quickw";

export default function(req) {
    kv.set("scan:user:1", "alice");
    kv.set("scan:user:2", "bob");
    kv.set("scan:user:3", "charlie");
    kv.set("scan:item:1", "widget");
    
    const userKeys = kv.scan("scan:user:");
    const itemKeys = kv.scan("scan:item:");
    const allKeys = kv.scan("scan:");
    
    return Response.json({ 
        userCount: userKeys.length,
        itemCount: itemKeys.length,
        totalCount: allKeys.length,
        hasUser1: userKeys.includes("scan:user:1"),
        hasItem1: itemKeys.includes("scan:item:1")
    });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"userCount":3' && \
    assert_contains "$response" '"itemCount":1' && \
    assert_contains "$response" '"totalCount":4' && \
    assert_contains "$response" '"hasUser1":true' && \
    assert_contains "$response" '"hasItem1":true'
}

# Test: KV scan with limit
test_kv_scan_limit() {
    local handler='import { kv } from "quickw";

export default function(req) {
    for (let i = 0; i < 10; i++) {
        kv.set("limit-test:" + i, "value" + i);
    }
    
    const limited = kv.scan("limit-test:", 3);
    const all = kv.scan("limit-test:");
    
    return Response.json({ 
        limitedCount: limited.length,
        allCount: all.length
    });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"limitedCount":3' && \
    assert_contains "$response" '"allCount":10'
}

# Test: KV entries returns key-value pairs
test_kv_entries() {
    local handler='import { kv } from "quickw";

export default function(req) {
    kv.set("entries:a", "value-a");
    kv.set("entries:b", "value-b");
    
    const entries = kv.entries("entries:");
    const hasCorrectStructure = entries.every(e => Array.isArray(e) && e.length === 2);
    const keys = entries.map(e => e[0]);
    const values = entries.map(e => e[1]);
    
    return Response.json({ 
        count: entries.length,
        hasCorrectStructure,
        hasKeyA: keys.includes("entries:a"),
        hasValueA: values.includes("value-a")
    });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"count":2' && \
    assert_contains "$response" '"hasCorrectStructure":true' && \
    assert_contains "$response" '"hasKeyA":true' && \
    assert_contains "$response" '"hasValueA":true'
}

# Test: KV TTL set and check
test_kv_ttl_set() {
    local handler='import { kv } from "quickw";

export default function(req) {
    kv.set("ttl-test", "expires-soon", 5000);
    const ttl = kv.ttl("ttl-test");
    const value = kv.get("ttl-test");
    
    // TTL should be close to 5000 (within 100ms tolerance)
    const ttlValid = ttl !== null && ttl > 4900 && ttl <= 5000;
    
    return Response.json({ 
        value,
        ttl,
        ttlValid
    });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"value":"expires-soon"' && \
    assert_contains "$response" '"ttlValid":true'
}

# Test: KV TTL returns null for keys without TTL
test_kv_ttl_no_expiry() {
    local handler='import { kv } from "quickw";

export default function(req) {
    kv.set("no-ttl-test", "permanent");
    const ttl = kv.ttl("no-ttl-test");
    const value = kv.get("no-ttl-test");
    
    return Response.json({ 
        value,
        ttl,
        ttlIsNull: ttl === null
    });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"value":"permanent"' && \
    assert_contains "$response" '"ttl":null' && \
    assert_contains "$response" '"ttlIsNull":true'
}

# Test: KV TTL expiration
test_kv_ttl_expiration() {
    local handler='import { kv } from "quickw";

export default async function(req) {
    kv.set("expire-test", "short-lived", 100);
    
    const before = {
        value: kv.get("expire-test"),
        exists: kv.exists("expire-test"),
        ttl: kv.ttl("expire-test")
    };
    
    // Wait for expiration
    await new Promise(resolve => setTimeout(resolve, 200));
    
    const after = {
        value: kv.get("expire-test"),
        exists: kv.exists("expire-test"),
        ttl: kv.ttl("expire-test")
    };
    
    return Response.json({ before, after });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    # Before expiration
    assert_contains "$response" '"value":"short-lived"' && \
    # After expiration - value should be null
    assert_contains "$response" '"after":{"value":null,"exists":false,"ttl":null}'
}

# Test: KV update resets TTL
test_kv_ttl_update() {
    local handler='import { kv } from "quickw";

export default async function(req) {
    kv.set("ttl-update-test", "initial", 100);
    
    // Wait 50ms
    await new Promise(resolve => setTimeout(resolve, 50));
    
    // Update with new TTL
    kv.set("ttl-update-test", "updated", 5000);
    
    // Wait another 100ms - original TTL would have expired
    await new Promise(resolve => setTimeout(resolve, 100));
    
    const value = kv.get("ttl-update-test");
    const ttl = kv.ttl("ttl-update-test");
    
    return Response.json({ 
        value,
        stillExists: value !== null,
        ttlValid: ttl !== null && ttl > 4000
    });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"value":"updated"' && \
    assert_contains "$response" '"stillExists":true' && \
    assert_contains "$response" '"ttlValid":true'
}

# Test: KV key size limit (128 bytes)
test_kv_key_size_limit() {
    local handler='import { kv } from "quickw";

export default function(req) {
    const key128 = "k".repeat(128);
    const key129 = "k".repeat(129);
    
    let set128Success = false;
    let set129Error = null;
    
    try {
        kv.set(key128, "value");
        set128Success = kv.get(key128) === "value";
    } catch (e) {
        set128Success = false;
    }
    
    try {
        kv.set(key129, "value");
        set129Error = "no error thrown";
    } catch (e) {
        set129Error = e.message;
    }
    
    return Response.json({ 
        set128Success,
        set129Error,
        key129Rejected: set129Error && set129Error.includes("128 bytes")
    });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"set128Success":true' && \
    assert_contains "$response" '"key129Rejected":true'
}

# Test: KV value size limit (1024 bytes)
test_kv_value_size_limit() {
    local handler='import { kv } from "quickw";

export default function(req) {
    const value1024 = "v".repeat(1024);
    const value1025 = "v".repeat(1025);
    
    let set1024Success = false;
    let set1025Error = null;
    
    try {
        kv.set("val-limit-test-ok", value1024);
        set1024Success = kv.get("val-limit-test-ok")?.length === 1024;
    } catch (e) {
        set1024Success = false;
    }
    
    try {
        kv.set("val-limit-test-fail", value1025);
        set1025Error = "no error thrown";
    } catch (e) {
        set1025Error = e.message;
    }
    
    return Response.json({ 
        set1024Success,
        set1025Error,
        value1025Rejected: set1025Error && set1025Error.includes("1024 bytes")
    });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"set1024Success":true' && \
    assert_contains "$response" '"value1025Rejected":true'
}

# Test: KV overwrite existing key
test_kv_overwrite() {
    local handler='import { kv } from "quickw";

export default function(req) {
    kv.set("overwrite-test", "original");
    const before = kv.get("overwrite-test");
    
    kv.set("overwrite-test", "updated");
    const after = kv.get("overwrite-test");
    
    return Response.json({ before, after });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"before":"original"' && \
    assert_contains "$response" '"after":"updated"'
}

# Test: KV persists across requests (shared state)
test_kv_shared_state() {
    # First handler sets a value
    local set_handler='import { kv } from "quickw";

export default function(req) {
    kv.set("shared-state-test", "set-by-handler-1");
    return Response.json({ set: true });
}'
    
    local set_id
    set_id=$(register_handler "$set_handler")
    [[ -z "$set_id" ]] && return 1
    
    # Execute first handler to set the value
    execute_handler "$set_id" > /dev/null
    
    # Second handler reads the value
    local get_handler='import { kv } from "quickw";

export default function(req) {
    const value = kv.get("shared-state-test");
    return Response.json({ value });
}'
    
    local get_id
    get_id=$(register_handler "$get_handler")
    [[ -z "$get_id" ]] && return 1
    
    local response
    response=$(execute_handler "$get_id")
    
    assert_contains "$response" '"value":"set-by-handler-1"'
}

# Test: KV LRU eviction (requires server started with small kv-size)
test_kv_lru_eviction() {
    local handler='import { kv } from "quickw";

export default function(req) {
    // This test assumes server is started with --kv-size 100
    // Fill with 50 entries
    for (let i = 0; i < 50; i++) {
        kv.set("lru-evict:" + i, "value" + i);
    }
    
    // Access key 0 to make it recently used
    kv.get("lru-evict:0");
    
    // Add 60 more entries to trigger eviction
    for (let i = 50; i < 110; i++) {
        kv.set("lru-evict:" + i, "value" + i);
    }
    
    // Key 0 should still exist (was recently accessed)
    // Key 10 should be evicted (not accessed, older)
    const key0 = kv.get("lru-evict:0");
    const key10 = kv.get("lru-evict:10");
    const key100 = kv.get("lru-evict:100");
    
    return Response.json({ 
        key0Exists: key0 !== null,
        key10Evicted: key10 === null,
        key100Exists: key100 !== null
    });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"key0Exists":true' && \
    assert_contains "$response" '"key10Evicted":true' && \
    assert_contains "$response" '"key100Exists":true'
}

# Test: KV empty string key and value
test_kv_empty_strings() {
    local handler='import { kv } from "quickw";

export default function(req) {
    // Empty value should work
    kv.set("empty-value-test", "");
    const emptyValue = kv.get("empty-value-test");
    
    return Response.json({ 
        emptyValue,
        emptyValueIsString: emptyValue === ""
    });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"emptyValue":""' && \
    assert_contains "$response" '"emptyValueIsString":true'
}

# Test: KV special characters in keys and values
test_kv_special_chars() {
    local handler='import { kv } from "quickw";

export default function(req) {
    const specialKey = "key:with/special\\chars!@#$%";
    const specialValue = "value\nwith\ttabs\rand\"quotes\"";
    
    kv.set(specialKey, specialValue);
    const retrieved = kv.get(specialKey);
    
    return Response.json({ 
        matches: retrieved === specialValue,
        hasNewline: retrieved.includes("\n"),
        hasTab: retrieved.includes("\t")
    });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"matches":true' && \
    assert_contains "$response" '"hasNewline":true' && \
    assert_contains "$response" '"hasTab":true'
}

# Test: KV JSON values (store and retrieve)
test_kv_json_values() {
    local handler='import { kv } from "quickw";

export default function(req) {
    const obj = { name: "test", count: 42, nested: { a: 1 } };
    kv.set("json-test", JSON.stringify(obj));
    
    const retrieved = kv.get("json-test");
    const parsed = JSON.parse(retrieved);
    
    return Response.json({ 
        name: parsed.name,
        count: parsed.count,
        nestedA: parsed.nested.a
    });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"name":"test"' && \
    assert_contains "$response" '"count":42' && \
    assert_contains "$response" '"nestedA":1'
}
