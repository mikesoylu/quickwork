# =============================================================================
# WEB STREAMS AND BLOB TESTS
# =============================================================================

# Test: Blob basic creation and properties
test_blob_basic() {
    local handler='export default async function(req) {
    const blob = new Blob(["Hello, ", "World!"], { type: "text/plain" });
    const text = await blob.text();
    return Response.json({ 
        size: blob.size,
        type: blob.type,
        text: text
    });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"size":13' && \
    assert_contains "$response" '"type":"text/plain"' && \
    assert_contains "$response" '"text":"Hello, World!"'
}

# Test: Blob arrayBuffer method
test_blob_arraybuffer() {
    local handler='export default async function(req) {
    const blob = new Blob(["ABC"]);
    const buffer = await blob.arrayBuffer();
    const bytes = new Uint8Array(buffer);
    return Response.json({ 
        byteLength: buffer.byteLength,
        bytes: Array.from(bytes)
    });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"byteLength":3' && \
    assert_contains "$response" '"bytes":[65,66,67]'
}

# Test: Blob bytes method
test_blob_bytes() {
    local handler='export default async function(req) {
    const blob = new Blob(["Hi"]);
    const bytes = await blob.bytes();
    return Response.json({ 
        isUint8Array: bytes instanceof Uint8Array,
        length: bytes.length,
        values: Array.from(bytes)
    });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"isUint8Array":true' && \
    assert_contains "$response" '"length":2' && \
    assert_contains "$response" '"values":[72,105]'
}

# Test: Blob slice method
test_blob_slice() {
    local handler='export default async function(req) {
    const blob = new Blob(["Hello, World!"]);
    const sliced = blob.slice(0, 5);
    const text = await sliced.text();
    const middleSlice = blob.slice(7, 12);
    const middleText = await middleSlice.text();
    return Response.json({ 
        originalSize: blob.size,
        slicedSize: sliced.size,
        slicedText: text,
        middleText: middleText
    });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"originalSize":13' && \
    assert_contains "$response" '"slicedSize":5' && \
    assert_contains "$response" '"slicedText":"Hello"' && \
    assert_contains "$response" '"middleText":"World"'
}

# Test: Blob slice with negative indices
test_blob_slice_negative() {
    local handler='export default async function(req) {
    const blob = new Blob(["Hello, World!"]);
    const lastFive = blob.slice(-6, -1);
    const text = await lastFive.text();
    return Response.json({ 
        size: lastFive.size,
        text: text
    });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"size":5' && \
    assert_contains "$response" '"text":"World"'
}

# Test: Blob from ArrayBuffer
test_blob_from_arraybuffer() {
    local handler='export default async function(req) {
    const buffer = new Uint8Array([72, 101, 108, 108, 111]).buffer;
    const blob = new Blob([buffer]);
    const text = await blob.text();
    return Response.json({ 
        size: blob.size,
        text: text
    });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"size":5' && \
    assert_contains "$response" '"text":"Hello"'
}

# Test: Blob from Uint8Array
test_blob_from_uint8array() {
    local handler='export default async function(req) {
    const bytes = new Uint8Array([87, 111, 114, 108, 100]);
    const blob = new Blob([bytes]);
    const text = await blob.text();
    return Response.json({ 
        size: blob.size,
        text: text
    });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"size":5' && \
    assert_contains "$response" '"text":"World"'
}

# Test: Blob from mixed parts
test_blob_mixed_parts() {
    local handler='export default async function(req) {
    const str = "Hello";
    const bytes = new Uint8Array([44, 32]); // ", "
    const blob2 = new Blob(["World"]);
    
    const combined = new Blob([str, bytes, blob2]);
    const text = await combined.text();
    
    return Response.json({ 
        size: combined.size,
        text: text
    });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"size":12' && \
    assert_contains "$response" '"text":"Hello, World"'
}

# Test: Blob stream method
test_blob_stream() {
    local handler='export default async function(req) {
    const blob = new Blob(["Stream", "Test"]);
    const stream = blob.stream();
    const reader = stream.getReader();
    
    let chunks = [];
    while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        chunks.push(new TextDecoder().decode(value));
    }
    
    return Response.json({ 
        chunkCount: chunks.length,
        combined: chunks.join("")
    });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"combined":"StreamTest"'
}

# Test: ReadableStream basic usage
test_readable_stream_basic() {
    local handler='export default async function(req) {
    const stream = new ReadableStream({
        start(controller) {
            controller.enqueue("chunk1");
            controller.enqueue("chunk2");
            controller.enqueue("chunk3");
            controller.close();
        }
    });
    
    const reader = stream.getReader();
    const chunks = [];
    
    while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        chunks.push(value);
    }
    
    return Response.json({ 
        chunks: chunks,
        locked: stream.locked
    });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"chunks":["chunk1","chunk2","chunk3"]' && \
    assert_contains "$response" '"locked":true'
}

# Test: ReadableStream with pull function
test_readable_stream_pull() {
    local handler='export default async function(req) {
    let count = 0;
    const stream = new ReadableStream({
        pull(controller) {
            count++;
            if (count <= 3) {
                controller.enqueue("item" + count);
            } else {
                controller.close();
            }
        }
    });
    
    const reader = stream.getReader();
    const items = [];
    
    while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        items.push(value);
    }
    
    return Response.json({ items: items });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"items":["item1","item2","item3"]'
}

# Test: ReadableStream async iterator
test_readable_stream_async_iterator() {
    local handler='export default async function(req) {
    const stream = new ReadableStream({
        start(controller) {
            controller.enqueue(1);
            controller.enqueue(2);
            controller.enqueue(3);
            controller.close();
        }
    });
    
    const values = [];
    for await (const chunk of stream) {
        values.push(chunk);
    }
    
    return Response.json({ values: values });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"values":[1,2,3]'
}

# Test: ReadableStream tee (clone)
test_readable_stream_tee() {
    local handler='export default async function(req) {
    const original = new ReadableStream({
        start(controller) {
            controller.enqueue("a");
            controller.enqueue("b");
            controller.close();
        }
    });
    
    const [branch1, branch2] = original.tee();
    
    const reader1 = branch1.getReader();
    const reader2 = branch2.getReader();
    
    const chunks1 = [];
    const chunks2 = [];
    
    while (true) {
        const { done, value } = await reader1.read();
        if (done) break;
        chunks1.push(value);
    }
    
    while (true) {
        const { done, value } = await reader2.read();
        if (done) break;
        chunks2.push(value);
    }
    
    return Response.json({ 
        branch1: chunks1,
        branch2: chunks2,
        equal: JSON.stringify(chunks1) === JSON.stringify(chunks2)
    });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"branch1":["a","b"]' && \
    assert_contains "$response" '"branch2":["a","b"]' && \
    assert_contains "$response" '"equal":true'
}

# Test: ReadableStream cancel
test_readable_stream_cancel() {
    local handler='export default async function(req) {
    let cancelled = false;
    const stream = new ReadableStream({
        start(controller) {
            controller.enqueue("data");
        },
        cancel(reason) {
            cancelled = true;
        }
    });
    
    await stream.cancel("user cancelled");
    
    return Response.json({ cancelled: true });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"cancelled":true'
}

# Test: ReadableStream.from static method
test_readable_stream_from() {
    local handler='export default async function(req) {
    async function* asyncGen() {
        yield 10;
        yield 20;
        yield 30;
    }
    
    const stream = ReadableStream.from(asyncGen());
    const reader = stream.getReader();
    const values = [];
    
    while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        values.push(value);
    }
    
    return Response.json({ values: values });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"values":[10,20,30]'
}

# Test: WritableStream basic usage
test_writable_stream_basic() {
    local handler='export default async function(req) {
    const chunks = [];
    const stream = new WritableStream({
        write(chunk) {
            chunks.push(chunk);
        }
    });
    
    const writer = stream.getWriter();
    await writer.write("first");
    await writer.write("second");
    await writer.write("third");
    await writer.close();
    
    return Response.json({ 
        chunks: chunks,
        locked: stream.locked
    });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"chunks":["first","second","third"]' && \
    assert_contains "$response" '"locked":true'
}

# Test: WritableStream with async write
test_writable_stream_async() {
    local handler='export default async function(req) {
    const results = [];
    const stream = new WritableStream({
        async write(chunk) {
            await new Promise(r => setTimeout(r, 10));
            results.push(chunk + "-processed");
        }
    });
    
    const writer = stream.getWriter();
    await writer.write("a");
    await writer.write("b");
    await writer.close();
    
    return Response.json({ results: results });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"results":["a-processed","b-processed"]'
}

# Test: WritableStream abort
test_writable_stream_abort() {
    local handler='export default async function(req) {
    let abortReason = null;
    const stream = new WritableStream({
        abort(reason) {
            abortReason = reason;
        }
    });
    
    await stream.abort("test abort");
    
    return Response.json({ aborted: true });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"aborted":true'
}

# Test: TransformStream basic usage
test_transform_stream_basic() {
    local handler='export default async function(req) {
    const transform = new TransformStream({
        transform(chunk, controller) {
            controller.enqueue(chunk.toUpperCase());
        }
    });
    
    const writer = transform.writable.getWriter();
    const reader = transform.readable.getReader();
    
    await writer.write("hello");
    await writer.write("world");
    await writer.close();
    
    const results = [];
    while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        results.push(value);
    }
    
    return Response.json({ results: results });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"results":["HELLO","WORLD"]'
}

# Test: TransformStream with flush
test_transform_stream_flush() {
    local handler='export default async function(req) {
    let sum = 0;
    const transform = new TransformStream({
        transform(chunk, controller) {
            sum += chunk;
            controller.enqueue(chunk);
        },
        flush(controller) {
            controller.enqueue("sum:" + sum);
        }
    });
    
    const writer = transform.writable.getWriter();
    const reader = transform.readable.getReader();
    
    await writer.write(1);
    await writer.write(2);
    await writer.write(3);
    await writer.close();
    
    const results = [];
    while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        results.push(value);
    }
    
    return Response.json({ results: results });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"results":[1,2,3,"sum:6"]'
}

# Test: ReadableStream pipeTo WritableStream
test_stream_pipe_to() {
    local handler='export default async function(req) {
    const chunks = [];
    
    const readable = new ReadableStream({
        start(controller) {
            controller.enqueue("pipe1");
            controller.enqueue("pipe2");
            controller.close();
        }
    });
    
    const writable = new WritableStream({
        write(chunk) {
            chunks.push(chunk);
        }
    });
    
    await readable.pipeTo(writable);
    
    return Response.json({ chunks: chunks });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"chunks":["pipe1","pipe2"]'
}

# Test: ReadableStream pipeThrough TransformStream
test_stream_pipe_through() {
    local handler='export default async function(req) {
    const readable = new ReadableStream({
        start(controller) {
            controller.enqueue("abc");
            controller.enqueue("def");
            controller.close();
        }
    });
    
    const transform = new TransformStream({
        transform(chunk, controller) {
            controller.enqueue(chunk.toUpperCase());
        }
    });
    
    const transformed = readable.pipeThrough(transform);
    const reader = transformed.getReader();
    
    const results = [];
    while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        results.push(value);
    }
    
    return Response.json({ results: results });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"results":["ABC","DEF"]'
}

# Test: ByteLengthQueuingStrategy
test_byte_length_queuing_strategy() {
    local handler='export default function(req) {
    const strategy = new ByteLengthQueuingStrategy({ highWaterMark: 1024 });
    const size = strategy.size(new Uint8Array(100));
    
    return Response.json({ 
        highWaterMark: strategy.highWaterMark,
        size: size
    });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"highWaterMark":1024' && \
    assert_contains "$response" '"size":100'
}

# Test: CountQueuingStrategy
test_count_queuing_strategy() {
    local handler='export default function(req) {
    const strategy = new CountQueuingStrategy({ highWaterMark: 10 });
    const size1 = strategy.size("any");
    const size2 = strategy.size([1,2,3]);
    
    return Response.json({ 
        highWaterMark: strategy.highWaterMark,
        size1: size1,
        size2: size2
    });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"highWaterMark":10' && \
    assert_contains "$response" '"size1":1' && \
    assert_contains "$response" '"size2":1'
}

# Test: TextEncoder (bundled with streams polyfill)
test_text_encoder() {
    local handler='export default function(req) {
    const encoder = new TextEncoder();
    const encoded = encoder.encode("Hello");
    
    return Response.json({ 
        encoding: encoder.encoding,
        length: encoded.length,
        bytes: Array.from(encoded)
    });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"encoding":"utf-8"' && \
    assert_contains "$response" '"length":5' && \
    assert_contains "$response" '"bytes":[72,101,108,108,111]'
}

# Test: ReadableStream error handling
test_readable_stream_error() {
    local handler='export default async function(req) {
    const stream = new ReadableStream({
        async start(controller) {
            controller.enqueue("ok");
            // Use setTimeout to ensure the chunk can be read before error
            await new Promise(resolve => setTimeout(resolve, 10));
            controller.error(new Error("stream error"));
        }
    });
    
    const reader = stream.getReader();
    const results = { chunks: [], error: null };
    
    try {
        while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            results.chunks.push(value);
        }
    } catch (e) {
        results.error = e.message;
    }
    
    return Response.json(results);
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"chunks":["ok"]' && \
    assert_contains "$response" '"error":"stream error"'
}

# Test: Multiple readers throw error (locked stream)
test_readable_stream_locked() {
    local handler='export default async function(req) {
    const stream = new ReadableStream({
        start(controller) {
            controller.enqueue("data");
            controller.close();
        }
    });
    
    const reader1 = stream.getReader();
    let secondReaderError = null;
    
    try {
        const reader2 = stream.getReader();
    } catch (e) {
        secondReaderError = e.message;
    }
    
    return Response.json({ 
        locked: stream.locked,
        errorThrown: secondReaderError !== null,
        errorMessage: secondReaderError
    });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"locked":true' && \
    assert_contains "$response" '"errorThrown":true'
}

# Test: Reader release lock
test_readable_stream_release_lock() {
    local handler='export default async function(req) {
    const stream = new ReadableStream({
        start(controller) {
            controller.enqueue("data");
            controller.close();
        }
    });
    
    const reader1 = stream.getReader();
    reader1.releaseLock();
    
    const reader2 = stream.getReader();
    const { value } = await reader2.read();
    
    return Response.json({ 
        value: value,
        success: true
    });
}'
    
    local id
    id=$(register_handler "$handler")
    [[ -z "$id" ]] && return 1
    
    local response
    response=$(execute_handler "$id")
    
    assert_contains "$response" '"value":"data"' && \
    assert_contains "$response" '"success":true'
}
