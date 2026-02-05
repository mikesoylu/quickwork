# =============================================================================
# EDGE CASE TESTS
# =============================================================================

# Test: Deep recursion (fib 25)
test_deep_recursion() {
    local handler='export default function(req) {
        function fib(n) {
            if (n <= 1) return n;
            return fib(n - 1) + fib(n - 2);
        }
        // fib(25) = 75025, requires many recursive calls
        const result = fib(25);
        return Response.json({ fib25: result });
    }'

    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1

    local response
    response=$(execute_handler "$id")

    assert_contains "$response" '"fib25":75025'
}

# Test: Generator function and iteration
test_generator_function() {
    local handler='export default function(req) {
        function* range(start, end) {
            for (let i = start; i < end; i++) yield i;
        }
        const nums = [...range(1, 6)];
        return Response.json({ nums: nums });
    }'

    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1

    local response
    response=$(execute_handler "$id")

    assert_contains "$response" '"nums":[1,2,3,4,5]'
}

# Test: Async generator with for-await-of
test_async_generator() {
    local handler='export default async function(req) {
        async function* asyncRange(start, end) {
            for (let i = start; i < end; i++) {
                await new Promise(r => setTimeout(r, 1));
                yield i;
            }
        }
        const nums = [];
        for await (const n of asyncRange(1, 4)) {
            nums.push(n);
        }
        return Response.json({ nums: nums });
    }'

    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1

    local response
    response=$(execute_handler "$id")

    assert_contains "$response" '"nums":[1,2,3]'
}

# Test: Proxy object with traps
test_proxy_object() {
    local handler='export default function(req) {
        const target = { x: 10, y: 20 };
        const handler = {
            get(obj, prop) {
                return prop in obj ? obj[prop] * 2 : 0;
            }
        };
        const proxy = new Proxy(target, handler);
        return Response.json({ x: proxy.x, y: proxy.y, z: proxy.z });
    }'

    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1

    local response
    response=$(execute_handler "$id")

    assert_contains "$response" '"x":20' && \
    assert_contains "$response" '"y":40' && \
    assert_contains "$response" '"z":0'
}

# Test: WeakMap and garbage collection hints
test_weakmap() {
    local handler='export default function(req) {
        const wm = new WeakMap();
        const obj1 = { id: 1 };
        const obj2 = { id: 2 };
        wm.set(obj1, "value1");
        wm.set(obj2, "value2");
        return Response.json({ 
            has1: wm.has(obj1), 
            has2: wm.has(obj2),
            val1: wm.get(obj1)
        });
    }'

    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1

    local response
    response=$(execute_handler "$id")

    assert_contains "$response" '"has1":true' && \
    assert_contains "$response" '"has2":true' && \
    assert_contains "$response" '"val1":"value1"'
}

# Test: Symbol as object key
test_symbol_keys() {
    local handler='export default function(req) {
        const sym = Symbol("mySymbol");
        const obj = { [sym]: "secret", visible: "public" };
        const keys = Object.keys(obj);
        const syms = Object.getOwnPropertySymbols(obj);
        return Response.json({ 
            keyCount: keys.length,
            symCount: syms.length,
            hasSecret: obj[syms[0]] === "secret"
        });
    }'

    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1

    local response
    response=$(execute_handler "$id")

    assert_contains "$response" '"keyCount":1' && \
    assert_contains "$response" '"symCount":1' && \
    assert_contains "$response" '"hasSecret":true'
}

# Test: BigInt arithmetic
test_bigint_arithmetic() {
    local handler='export default function(req) {
        const big1 = 9007199254740993n; // Larger than Number.MAX_SAFE_INTEGER
        const big2 = 9007199254740993n;
        const sum = big1 + big2;
        const product = big1 * 2n;
        return Response.json({ 
            sumStr: sum.toString(),
            productStr: product.toString(),
            isEqual: big1 === big2
        });
    }'

    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1

    local response
    response=$(execute_handler "$id")

    assert_contains "$response" '"sumStr":"18014398509481986"' && \
    assert_contains "$response" '"productStr":"18014398509481986"' && \
    assert_contains "$response" '"isEqual":true'
}

# Test: Reflect API
test_reflect_api() {
    local handler='export default function(req) {
        const obj = { x: 1 };
        Reflect.set(obj, "y", 2);
        const has = Reflect.has(obj, "y");
        const keys = Reflect.ownKeys(obj);
        Reflect.deleteProperty(obj, "x");
        return Response.json({ 
            has: has, 
            keys: keys, 
            afterDelete: Object.keys(obj)
        });
    }'

    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1

    local response
    response=$(execute_handler "$id")

    assert_contains "$response" '"has":true' && \
    assert_contains "$response" '"keys":["x","y"]' && \
    assert_contains "$response" '"afterDelete":["y"]'
}

# Test: Promise.race with timeout
test_promise_race() {
    local handler='export default async function(req) {
        const slow = new Promise(r => setTimeout(() => r("slow"), 100));
        const fast = new Promise(r => setTimeout(() => r("fast"), 10));
        const winner = await Promise.race([slow, fast]);
        return Response.json({ winner: winner });
    }'

    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1

    local response
    response=$(execute_handler "$id")

    assert_contains "$response" '"winner":"fast"'
}

# Test: Promise.allSettled with mixed results
test_promise_allsettled() {
    local handler='export default async function(req) {
        const results = await Promise.allSettled([
            Promise.resolve("success"),
            Promise.reject("failure"),
            Promise.resolve(42)
        ]);
        return Response.json({ 
            statuses: results.map(r => r.status),
            values: results.filter(r => r.status === "fulfilled").map(r => r.value)
        });
    }'

    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1

    local response
    response=$(execute_handler "$id")

    assert_contains "$response" '"statuses":["fulfilled","rejected","fulfilled"]' && \
    assert_contains "$response" '"values":["success",42]'
}

# Test: Destructuring with defaults and rest
test_advanced_destructuring() {
    local handler='export default function(req) {
        const obj = { a: 1, b: 2, c: 3, d: 4 };
        const { a, b = 10, e = 5, ...rest } = obj;
        const arr = [1, 2, 3, 4, 5];
        const [first, , third, ...remaining] = arr;
        return Response.json({ 
            a, b, e, rest, first, third, remaining 
        });
    }'

    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1

    local response
    response=$(execute_handler "$id")

    assert_contains "$response" '"a":1' && \
    assert_contains "$response" '"b":2' && \
    assert_contains "$response" '"e":5' && \
    assert_contains "$response" '"first":1' && \
    assert_contains "$response" '"third":3' && \
    assert_contains "$response" '"remaining":[4,5]'
}

# Test: Tagged template literals
test_tagged_template() {
    local handler='export default function(req) {
        function highlight(strings, ...values) {
            return strings.reduce((acc, str, i) => 
                acc + str + (values[i] ? `**${values[i]}**` : ""), "");
        }
        const name = "World";
        const count = 42;
        const result = highlight`Hello ${name}, you have ${count} messages`;
        return Response.json({ result: result });
    }'

    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1

    local response
    response=$(execute_handler "$id")

    assert_contains "$response" 'Hello **World**, you have **42** messages'
}

# Test: Nullish coalescing and optional chaining deep
test_nullish_and_optional() {
    local handler='export default function(req) {
        const obj = { 
            a: { b: { c: null } },
            x: 0,
            y: "",
            z: undefined
        };
        return Response.json({
            deep: obj?.a?.b?.c ?? "default",
            missing: obj?.a?.b?.d?.e ?? "not found",
            zero: obj.x ?? "fallback",
            empty: obj.y ?? "fallback", 
            undef: obj.z ?? "was undefined"
        });
    }'

    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1

    local response
    response=$(execute_handler "$id")

    assert_contains "$response" '"deep":"default"' && \
    assert_contains "$response" '"missing":"not found"' && \
    assert_contains "$response" '"zero":0' && \
    assert_contains "$response" '"empty":""' && \
    assert_contains "$response" '"undef":"was undefined"'
}

# Test: Closure preserving state across handler calls (should NOT share state)
test_closure_isolation() {
    local handler='let counter = 0;
export default function(req) {
    counter++;
    return Response.json({ counter: counter });
}'

    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1

    # Each execution should be isolated - counter should be 1 each time
    # (unless state leaks between executions)
    local r1 r2 r3
    r1=$(execute_handler "$id")
    r2=$(execute_handler "$id")
    r3=$(execute_handler "$id")

    # If properly isolated, all should be 1
    # If state leaks, they would be 1, 2, 3
    local c1 c2 c3
    c1=$(echo "$r1" | grep -o '"counter":[0-9]*' | cut -d: -f2)
    c2=$(echo "$r2" | grep -o '"counter":[0-9]*' | cut -d: -f2)
    c3=$(echo "$r3" | grep -o '"counter":[0-9]*' | cut -d: -f2)

    # For security, each should start fresh (counter=1)
    [[ "$c1" == "1" && "$c2" == "1" && "$c3" == "1" ]]
}

# Test: Error in async function properly rejects
test_async_error_rejection() {
    local handler='export default async function(req) {
        await Promise.resolve();
        throw new Error("async boom");
    }'

    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1

    local response
    response=$(execute_handler_with_headers "$id")

    assert_contains "$response" "500" || assert_contains "$response" "error" || assert_contains "$response" "boom"
}

# Test: Nested Promise chains
test_nested_promise_chains() {
    local handler='export default async function(req) {
        const result = await Promise.resolve(1)
            .then(x => Promise.resolve(x + 1))
            .then(x => Promise.resolve(x * 2))
            .then(x => Promise.resolve(x + 10))
            .then(x => ({ final: x }));
        return Response.json(result);
    }'

    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1

    local response
    response=$(execute_handler "$id")

    # (1+1)*2+10 = 14
    assert_contains "$response" '"final":14'
}

# Test: Array methods chaining (map, filter, reduce)
test_array_method_chaining() {
    local handler='export default function(req) {
        const result = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
            .filter(x => x % 2 === 0)
            .map(x => x * x)
            .reduce((acc, x) => acc + x, 0);
        return Response.json({ sumOfEvenSquares: result });
    }'

    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1

    local response
    response=$(execute_handler "$id")

    # 4 + 16 + 36 + 64 + 100 = 220
    assert_contains "$response" '"sumOfEvenSquares":220'
}

# Test: RegExp with named capture groups
test_regexp_named_groups() {
    local handler='export default function(req) {
        const re = /(?<year>\d{4})-(?<month>\d{2})-(?<day>\d{2})/;
        const match = re.exec("2024-12-25");
        return Response.json({
            year: match.groups.year,
            month: match.groups.month,
            day: match.groups.day
        });
    }'

    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1

    local response
    response=$(execute_handler "$id")

    assert_contains "$response" '"year":"2024"' && \
    assert_contains "$response" '"month":"12"' && \
    assert_contains "$response" '"day":"25"'
}

# Test: Object.fromEntries and Object.entries round-trip
test_object_entries_roundtrip() {
    local handler='export default function(req) {
        const obj = { a: 1, b: 2, c: 3 };
        const entries = Object.entries(obj);
        const doubled = entries.map(([k, v]) => [k, v * 2]);
        const result = Object.fromEntries(doubled);
        return Response.json(result);
    }'

    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1

    local response
    response=$(execute_handler "$id")

    assert_contains "$response" '"a":2' && \
    assert_contains "$response" '"b":4' && \
    assert_contains "$response" '"c":6'
}

# Test: Class with private fields (ES2022)
test_class_private_fields() {
    local handler='export default function(req) {
        class Counter {
            #count = 0;
            increment() { this.#count++; }
            get value() { return this.#count; }
        }
        const c = new Counter();
        c.increment();
        c.increment();
        c.increment();
        return Response.json({ value: c.value });
    }'

    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1

    local response
    response=$(execute_handler "$id")

    assert_contains "$response" '"value":3'
}
