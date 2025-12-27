#include "js_bindings.hpp"
#include "js_runtime.hpp"
#include "kv_store.hpp"

extern "C" {
#include "quickjs.h"
}

#include <curl/curl.h>
#include <openssl/rand.h>
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <map>
#include <sstream>
#include <thread>
#include <unordered_map>
#include <vector>

namespace quickwork::bindings {

// Console implementation
static JSValue js_console_log(JSContext* ctx, JSValueConst /*this_val*/,
                              int argc, JSValueConst* argv)
{
    for (int i = 0; i < argc; i++) {
        if (i > 0) std::cout << " ";
        const char* str = JS_ToCString(ctx, argv[i]);
        if (str) {
            std::cout << str;
            JS_FreeCString(ctx, str);
        }
    }
    std::cout << std::endl;
    return JS_UNDEFINED;
}

static JSValue js_console_error(JSContext* ctx, JSValueConst /*this_val*/,
                                int argc, JSValueConst* argv)
{
    for (int i = 0; i < argc; i++) {
        if (i > 0) std::cerr << " ";
        const char* str = JS_ToCString(ctx, argv[i]);
        if (str) {
            std::cerr << str;
            JS_FreeCString(ctx, str);
        }
    }
    std::cerr << std::endl;
    return JS_UNDEFINED;
}

void setup_console(JSContext* ctx) {
    JSValue global = JS_GetGlobalObject(ctx);
    JSValue console = JS_NewObject(ctx);

    JS_SetPropertyStr(ctx, console, "log",
        JS_NewCFunction(ctx, js_console_log, "log", 1));
    JS_SetPropertyStr(ctx, console, "info",
        JS_NewCFunction(ctx, js_console_log, "info", 1));
    JS_SetPropertyStr(ctx, console, "warn",
        JS_NewCFunction(ctx, js_console_error, "warn", 1));
    JS_SetPropertyStr(ctx, console, "error",
        JS_NewCFunction(ctx, js_console_error, "error", 1));

    JS_SetPropertyStr(ctx, global, "console", console);
    JS_FreeValue(ctx, global);
}

// ============================================================================
// Crypto API implementation (crypto.getRandomValues)
// ============================================================================

static JSValue js_crypto_getRandomValues(JSContext* ctx, JSValueConst /*this_val*/,
                                          int argc, JSValueConst* argv)
{
    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "crypto.getRandomValues requires 1 argument");
    }

    // Must be a TypedArray (Uint8Array, Uint16Array, Uint32Array, etc.)
    size_t byte_offset = 0;
    size_t byte_length = 0;
    size_t bytes_per_element = 0;
    
    JSValue buffer = JS_GetTypedArrayBuffer(ctx, argv[0], &byte_offset, &byte_length, &bytes_per_element);
    if (JS_IsException(buffer)) {
        return JS_ThrowTypeError(ctx, "crypto.getRandomValues: argument must be a TypedArray");
    }
    
    // Get the underlying buffer data
    size_t buffer_size = 0;
    uint8_t* buf = JS_GetArrayBuffer(ctx, &buffer_size, buffer);
    JS_FreeValue(ctx, buffer);
    
    if (!buf) {
        return JS_ThrowTypeError(ctx, "crypto.getRandomValues: failed to get array buffer");
    }
    
    // Check quota (max 65536 bytes as per Web Crypto spec)
    if (byte_length > 65536) {
        return JS_ThrowRangeError(ctx, "crypto.getRandomValues: quota exceeded (max 65536 bytes)");
    }
    
    // Fill with random bytes using OpenSSL
    if (RAND_bytes(buf + byte_offset, static_cast<int>(byte_length)) != 1) {
        return JS_ThrowInternalError(ctx, "crypto.getRandomValues: failed to generate random bytes");
    }
    
    // Return the same array (as per spec)
    return JS_DupValue(ctx, argv[0]);
}

static JSValue js_crypto_randomUUID(JSContext* ctx, JSValueConst /*this_val*/,
                                     int /*argc*/, JSValueConst* /*argv*/)
{
    // Generate a UUID v4
    uint8_t bytes[16];
    if (RAND_bytes(bytes, 16) != 1) {
        return JS_ThrowInternalError(ctx, "crypto.randomUUID: failed to generate random bytes");
    }
    
    // Set version (4) and variant (RFC 4122)
    bytes[6] = (bytes[6] & 0x0f) | 0x40;  // Version 4
    bytes[8] = (bytes[8] & 0x3f) | 0x80;  // Variant 1
    
    // Format as UUID string
    char uuid_str[37];
    snprintf(uuid_str, sizeof(uuid_str),
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             bytes[0], bytes[1], bytes[2], bytes[3],
             bytes[4], bytes[5],
             bytes[6], bytes[7],
             bytes[8], bytes[9],
             bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]);
    
    return JS_NewString(ctx, uuid_str);
}

void setup_crypto(JSContext* ctx) {
    JSValue global = JS_GetGlobalObject(ctx);
    JSValue crypto = JS_NewObject(ctx);
    
    JS_SetPropertyStr(ctx, crypto, "getRandomValues",
        JS_NewCFunction(ctx, js_crypto_getRandomValues, "getRandomValues", 1));
    JS_SetPropertyStr(ctx, crypto, "randomUUID",
        JS_NewCFunction(ctx, js_crypto_randomUUID, "randomUUID", 0));
    
    JS_SetPropertyStr(ctx, global, "crypto", crypto);
    JS_FreeValue(ctx, global);
}

// Request class
static JSClassID js_request_class_id;

static void js_request_finalizer(JSRuntime* /*rt*/, JSValue val) {
    auto* req = static_cast<HttpRequest*>(JS_GetOpaque(val, js_request_class_id));
    delete req;
}

static JSClassDef js_request_class = {
    .class_name = "Request",
    .finalizer = js_request_finalizer,
};

static JSValue js_request_get_method(JSContext* ctx, JSValueConst this_val) {
    auto* req = static_cast<HttpRequest*>(JS_GetOpaque(this_val, js_request_class_id));
    if (!req) return JS_UNDEFINED;
    return JS_NewString(ctx, req->method.c_str());
}

static JSValue js_request_get_url(JSContext* ctx, JSValueConst this_val) {
    auto* req = static_cast<HttpRequest*>(JS_GetOpaque(this_val, js_request_class_id));
    if (!req) return JS_UNDEFINED;
    return JS_NewString(ctx, req->url.c_str());
}

static JSValue js_request_get_body(JSContext* ctx, JSValueConst this_val) {
    auto* req = static_cast<HttpRequest*>(JS_GetOpaque(this_val, js_request_class_id));
    if (!req) return JS_UNDEFINED;
    return JS_NewString(ctx, req->body.c_str());
}

static JSValue js_request_get_headers(JSContext* ctx, JSValueConst this_val) {
    auto* req = static_cast<HttpRequest*>(JS_GetOpaque(this_val, js_request_class_id));
    if (!req) return JS_UNDEFINED;

    JSValue headers = JS_NewObject(ctx);
    for (const auto& [key, value] : req->headers) {
        JS_SetPropertyStr(ctx, headers, key.c_str(), JS_NewString(ctx, value.c_str()));
    }
    return headers;
}

static JSValue js_request_json(JSContext* ctx, JSValueConst this_val,
                               int /*argc*/, JSValueConst* /*argv*/)
{
    auto* req = static_cast<HttpRequest*>(JS_GetOpaque(this_val, js_request_class_id));
    if (!req) return JS_UNDEFINED;

    return JS_ParseJSON(ctx, req->body.c_str(), req->body.size(), "<json>");
}

static const JSCFunctionListEntry js_request_proto_funcs[] = {
    JS_CGETSET_DEF("method", js_request_get_method, nullptr),
    JS_CGETSET_DEF("url", js_request_get_url, nullptr),
    JS_CGETSET_DEF("body", js_request_get_body, nullptr),
    JS_CGETSET_DEF("headers", js_request_get_headers, nullptr),
    JS_CFUNC_DEF("json", 0, js_request_json),
};

void setup_request_class(JSContext* ctx) {
    JS_NewClassID(&js_request_class_id);
    JS_NewClass(JS_GetRuntime(ctx), js_request_class_id, &js_request_class);

    JSValue proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, proto, js_request_proto_funcs,
                               sizeof(js_request_proto_funcs) / sizeof(js_request_proto_funcs[0]));
    JS_SetClassProto(ctx, js_request_class_id, proto);
}

JSValue create_request(JSContext* ctx, const HttpRequest& request) {
    JSValue obj = JS_NewObjectClass(ctx, static_cast<int>(js_request_class_id));
    auto* req_copy = new HttpRequest(request);
    JS_SetOpaque(obj, req_copy);
    return obj;
}

// Response class - for creating responses in JS
static JSClassID js_response_class_id;

static void js_response_finalizer(JSRuntime* /*rt*/, JSValue /*val*/) {
    // Response data is managed by the HttpResponse struct
}

static JSClassDef js_response_class = {
    .class_name = "Response",
    .finalizer = js_response_finalizer,
};

static JSValue js_response_constructor(JSContext* ctx, JSValueConst /*new_target*/,
                                       int argc, JSValueConst* argv)
{
    JSValue obj = JS_NewObject(ctx);

    // Default values
    JS_SetPropertyStr(ctx, obj, "status", JS_NewInt32(ctx, 200));
    JS_SetPropertyStr(ctx, obj, "body", JS_NewString(ctx, ""));
    JS_SetPropertyStr(ctx, obj, "headers", JS_NewObject(ctx));

    if (argc >= 1) {
        const char* body = JS_ToCString(ctx, argv[0]);
        if (body) {
            JS_SetPropertyStr(ctx, obj, "body", JS_NewString(ctx, body));
            JS_FreeCString(ctx, body);
        }
    }

    if (argc >= 2 && JS_IsObject(argv[1])) {
        // Options object
        JSValue status_val = JS_GetPropertyStr(ctx, argv[1], "status");
        if (JS_IsNumber(status_val)) {
            JS_SetPropertyStr(ctx, obj, "status", JS_DupValue(ctx, status_val));
        }
        JS_FreeValue(ctx, status_val);

        JSValue headers_val = JS_GetPropertyStr(ctx, argv[1], "headers");
        if (JS_IsObject(headers_val)) {
            JS_SetPropertyStr(ctx, obj, "headers", JS_DupValue(ctx, headers_val));
        }
        JS_FreeValue(ctx, headers_val);
    }

    return obj;
}

static JSValue js_response_json(JSContext* ctx, JSValueConst /*this_val*/,
                                int argc, JSValueConst* argv)
{
    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "Response.json requires at least 1 argument");
    }

    JSValue json_str = JS_JSONStringify(ctx, argv[0], JS_UNDEFINED, JS_UNDEFINED);
    if (JS_IsException(json_str)) {
        return json_str;
    }

    JSValue obj = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, obj, "status", JS_NewInt32(ctx, 200));
    JS_SetPropertyStr(ctx, obj, "body", json_str);

    JSValue headers = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, headers, "Content-Type", JS_NewString(ctx, "application/json"));
    JS_SetPropertyStr(ctx, obj, "headers", headers);

    if (argc >= 2 && JS_IsObject(argv[1])) {
        JSValue status_val = JS_GetPropertyStr(ctx, argv[1], "status");
        if (JS_IsNumber(status_val)) {
            JS_SetPropertyStr(ctx, obj, "status", JS_DupValue(ctx, status_val));
        }
        JS_FreeValue(ctx, status_val);
    }

    return obj;
}

void setup_response_class(JSContext* ctx) {
    JS_NewClassID(&js_response_class_id);
    JS_NewClass(JS_GetRuntime(ctx), js_response_class_id, &js_response_class);

    JSValue global = JS_GetGlobalObject(ctx);

    // Response constructor
    JSValue response_ctor = JS_NewCFunction2(ctx, js_response_constructor, "Response", 2,
                                              JS_CFUNC_constructor, 0);

    // Static methods
    JS_SetPropertyStr(ctx, response_ctor, "json",
        JS_NewCFunction(ctx, js_response_json, "json", 2));

    JS_SetPropertyStr(ctx, global, "Response", response_ctor);
    JS_FreeValue(ctx, global);
}

// ============================================================================
// StreamResponse for SSE streaming
// ============================================================================

static JSClassID js_stream_response_class_id;

// StreamResponseData is defined in js_bindings.hpp

static void js_stream_response_finalizer(JSRuntime* /*rt*/, JSValue val) {
    auto* data = static_cast<StreamResponseData*>(JS_GetOpaque(val, js_stream_response_class_id));
    delete data;
}

static JSClassDef js_stream_response_class = {
    .class_name = "StreamResponse",
    .finalizer = js_stream_response_finalizer,
};

static JSValue js_stream_response_write(JSContext* ctx, JSValueConst this_val,
                                        int argc, JSValueConst* argv) {
    auto* data = static_cast<StreamResponseData*>(JS_GetOpaque(this_val, js_stream_response_class_id));
    if (!data) return JS_EXCEPTION;
    
    if (data->closed) {
        return JS_ThrowTypeError(ctx, "StreamResponse is already closed");
    }
    
    if (argc >= 1) {
        const char* chunk = JS_ToCString(ctx, argv[0]);
        if (chunk) {
            if (data->writer) {
                data->writer(chunk);
            }
            JS_FreeCString(ctx, chunk);
        }
    }
    
    return JS_DupValue(ctx, this_val);  // Return this for chaining
}

static JSValue js_stream_response_close(JSContext* ctx, JSValueConst this_val,
                                        int /*argc*/, JSValueConst* /*argv*/) {
    auto* data = static_cast<StreamResponseData*>(JS_GetOpaque(this_val, js_stream_response_class_id));
    if (!data) return JS_EXCEPTION;
    
    data->closed = true;
    return JS_DupValue(ctx, this_val);
}

// Forward declaration
quickwork::StreamWriter get_current_stream_writer();

static JSValue js_stream_response_constructor(JSContext* ctx, JSValueConst /*new_target*/,
                                              int argc, JSValueConst* argv) {
    JSValue obj = JS_NewObjectClass(ctx, js_stream_response_class_id);
    if (JS_IsException(obj)) return obj;
    
    auto* data = new StreamResponseData();
    
    // Get the stream writer for this context
    data->writer = get_current_stream_writer();
    
    // Default SSE headers
    data->headers["Content-Type"] = "text/event-stream";
    data->headers["Cache-Control"] = "no-cache";
    data->headers["Connection"] = "keep-alive";
    
    if (argc >= 1 && JS_IsObject(argv[0])) {
        // Options object
        JSValue status_val = JS_GetPropertyStr(ctx, argv[0], "status");
        if (JS_IsNumber(status_val)) {
            int32_t status;
            JS_ToInt32(ctx, &status, status_val);
            data->status = status;
        }
        JS_FreeValue(ctx, status_val);
        
        JSValue headers_val = JS_GetPropertyStr(ctx, argv[0], "headers");
        if (JS_IsObject(headers_val)) {
            JSPropertyEnum* props = nullptr;
            uint32_t prop_count = 0;
            if (JS_GetOwnPropertyNames(ctx, &props, &prop_count, headers_val,
                                       JS_GPN_STRING_MASK | JS_GPN_ENUM_ONLY) == 0) {
                for (uint32_t i = 0; i < prop_count; i++) {
                    const char* key = JS_AtomToCString(ctx, props[i].atom);
                    if (key) {
                        JSValue val = JS_GetProperty(ctx, headers_val, props[i].atom);
                        const char* val_str = JS_ToCString(ctx, val);
                        if (val_str) {
                            data->headers[key] = val_str;
                            JS_FreeCString(ctx, val_str);
                        }
                        JS_FreeValue(ctx, val);
                        JS_FreeCString(ctx, key);
                    }
                }
                for (uint32_t i = 0; i < prop_count; i++) {
                    JS_FreeAtom(ctx, props[i].atom);
                }
                js_free(ctx, props);
            }
        }
        JS_FreeValue(ctx, headers_val);
    }
    
    JS_SetOpaque(obj, data);
    
    // Mark as streaming response
    JS_SetPropertyStr(ctx, obj, "__streaming__", JS_TRUE);
    JS_SetPropertyStr(ctx, obj, "status", JS_NewInt32(ctx, data->status));
    
    return obj;
}

// Helper to send SSE event
static JSValue js_stream_response_send_event(JSContext* ctx, JSValueConst this_val,
                                             int argc, JSValueConst* argv) {
    auto* data = static_cast<StreamResponseData*>(JS_GetOpaque(this_val, js_stream_response_class_id));
    if (!data) return JS_EXCEPTION;
    
    if (data->closed) {
        return JS_ThrowTypeError(ctx, "StreamResponse is already closed");
    }
    
    std::string event;
    
    // Check if first arg is an object with data/event/id fields
    if (argc >= 1 && JS_IsObject(argv[0])) {
        JSValue event_type = JS_GetPropertyStr(ctx, argv[0], "event");
        if (!JS_IsUndefined(event_type)) {
            const char* et = JS_ToCString(ctx, event_type);
            if (et) {
                event += "event: ";
                event += et;
                event += "\n";
                JS_FreeCString(ctx, et);
            }
        }
        JS_FreeValue(ctx, event_type);
        
        JSValue id_val = JS_GetPropertyStr(ctx, argv[0], "id");
        if (!JS_IsUndefined(id_val)) {
            const char* id = JS_ToCString(ctx, id_val);
            if (id) {
                event += "id: ";
                event += id;
                event += "\n";
                JS_FreeCString(ctx, id);
            }
        }
        JS_FreeValue(ctx, id_val);
        
        JSValue data_val = JS_GetPropertyStr(ctx, argv[0], "data");
        if (!JS_IsUndefined(data_val)) {
            // If data is an object, JSON stringify it
            if (JS_IsObject(data_val) && !JS_IsNull(data_val)) {
                JSValue json = JS_JSONStringify(ctx, data_val, JS_UNDEFINED, JS_UNDEFINED);
                if (!JS_IsException(json)) {
                    const char* json_str = JS_ToCString(ctx, json);
                    if (json_str) {
                        event += "data: ";
                        event += json_str;
                        event += "\n";
                        JS_FreeCString(ctx, json_str);
                    }
                }
                JS_FreeValue(ctx, json);
            } else {
                const char* d = JS_ToCString(ctx, data_val);
                if (d) {
                    event += "data: ";
                    event += d;
                    event += "\n";
                    JS_FreeCString(ctx, d);
                }
            }
        }
        JS_FreeValue(ctx, data_val);
    } else if (argc >= 1) {
        // Simple string data
        const char* d = JS_ToCString(ctx, argv[0]);
        if (d) {
            event += "data: ";
            event += d;
            event += "\n";
            JS_FreeCString(ctx, d);
        }
    }
    
    event += "\n";  // End of event
    if (data->writer) {
        data->writer(event);
    }
    
    return JS_DupValue(ctx, this_val);
}

void setup_stream_response_class(JSContext* ctx) {
    JS_NewClassID(&js_stream_response_class_id);
    JS_NewClass(JS_GetRuntime(ctx), js_stream_response_class_id, &js_stream_response_class);
    
    JSValue global = JS_GetGlobalObject(ctx);
    
    // StreamResponse prototype
    JSValue proto = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, proto, "write", 
        JS_NewCFunction(ctx, js_stream_response_write, "write", 1));
    JS_SetPropertyStr(ctx, proto, "close",
        JS_NewCFunction(ctx, js_stream_response_close, "close", 0));
    JS_SetPropertyStr(ctx, proto, "send",
        JS_NewCFunction(ctx, js_stream_response_send_event, "send", 1));
    JS_SetPropertyStr(ctx, proto, "enqueue",
        JS_NewCFunction(ctx, js_stream_response_send_event, "enqueue", 1));
    
    JS_SetClassProto(ctx, js_stream_response_class_id, proto);
    
    // StreamResponse constructor
    JSValue stream_response_ctor = JS_NewCFunction2(ctx, js_stream_response_constructor, 
                                                     "StreamResponse", 1,
                                                     JS_CFUNC_constructor, 0);
    
    JS_SetPropertyStr(ctx, global, "StreamResponse", stream_response_ctor);
    JS_FreeValue(ctx, global);
}

// Get stream data from JS object
StreamResponseData* get_stream_response_data(JSContext* /*ctx*/, JSValue obj) {
    return static_cast<StreamResponseData*>(JS_GetOpaque(obj, js_stream_response_class_id));
}

// Thread-local stream writer for the current context
static thread_local quickwork::StreamWriter g_current_stream_writer;

void set_stream_writer(JSContext* /*ctx*/, quickwork::StreamWriter writer) {
    g_current_stream_writer = std::move(writer);
}

quickwork::StreamWriter get_current_stream_writer() {
    return g_current_stream_writer;
}

// ============================================================================
// ReadableStream implementation for streaming fetch
// ============================================================================

static JSClassID js_readable_stream_class_id;
static JSClassID js_readable_stream_reader_class_id;

// Shared state for streaming - curl writes here, reader reads from here
struct StreamState {
    std::mutex mutex;
    std::condition_variable cv;
    std::queue<std::string> chunks;
    bool done = false;
    bool error = false;
    std::string error_message;
    CURL* curl = nullptr;
    struct curl_slist* headers = nullptr;
    bool curl_started = false;
    bool curl_finished = false;
    bool headers_received = false;  // Set when we get HTTP status line
    
    // Request data (kept alive for curl)
    std::string url;
    std::string method;
    std::string body;
    std::unordered_map<std::string, std::string> request_headers;
    std::unordered_map<std::string, std::string> response_headers;
    long status_code = 0;
};

// Pending fetch operation for async resolution
struct PendingFetch {
    std::shared_ptr<StreamState> stream_state;
    JSValue resolve_func;
    JSValue reject_func;
    JSContext* ctx;
};

// Per-context pending fetches stored similarly to timers
struct FetchState {
    std::vector<PendingFetch> pending;
};

static JSClassID js_fetch_state_class_id;
static bool fetch_class_registered = false;

static void js_fetch_state_finalizer(JSRuntime* /*rt*/, JSValue val) {
    auto* state = static_cast<FetchState*>(JS_GetOpaque(val, js_fetch_state_class_id));
    // Note: pending fetches should be cleaned up before context destruction
    delete state;
}

static JSClassDef js_fetch_state_class = {
    .class_name = "FetchState",
    .finalizer = js_fetch_state_finalizer,
};

static FetchState* get_fetch_state(JSContext* ctx) {
    JSValue global = JS_GetGlobalObject(ctx);
    JSValue state_val = JS_GetPropertyStr(ctx, global, "__fetch_state__");
    JS_FreeValue(ctx, global);
    
    if (JS_IsUndefined(state_val)) {
        return nullptr;
    }
    
    auto* state = static_cast<FetchState*>(JS_GetOpaque(state_val, js_fetch_state_class_id));
    JS_FreeValue(ctx, state_val);
    return state;
}

struct ReadableStreamData {
    std::shared_ptr<StreamState> state;
    bool locked = false;
};

struct ReadableStreamReaderData {
    std::shared_ptr<StreamState> state;
    JSContext* ctx;
};

// Curl callback that pushes chunks to the stream state
static size_t stream_write_callback(char* ptr, size_t size, size_t nmemb, void* userdata) {
    auto* state = static_cast<StreamState*>(userdata);
    size_t total = size * nmemb;
    
    std::lock_guard<std::mutex> lock(state->mutex);
    state->chunks.push(std::string(ptr, total));
    state->cv.notify_one();
    
    return total;
}

static size_t stream_header_callback(char* buffer, size_t size, size_t nitems, void* userdata) {
    auto* state = static_cast<StreamState*>(userdata);
    std::string header(buffer, size * nitems);
    
    while (!header.empty() && (header.back() == '\r' || header.back() == '\n')) {
        header.pop_back();
    }
    
    // Empty line signals end of headers for current response
    // But don't mark as received until we have a final (non-redirect) status
    if (header.empty()) {
        std::lock_guard<std::mutex> lock(state->mutex);
        // Only mark headers_received if this is a final response (not a redirect)
        // Status codes 3xx are redirects that curl will follow
        if (state->status_code < 300 || state->status_code >= 400) {
            state->headers_received = true;
            state->cv.notify_all();
        }
        return size * nitems;
    }
    
    // Parse HTTP status line (e.g., "HTTP/1.1 200 OK")
    if (header.substr(0, 5) == "HTTP/") {
        size_t space1 = header.find(' ');
        if (space1 != std::string::npos) {
            size_t space2 = header.find(' ', space1 + 1);
            std::string status_str = header.substr(space1 + 1, space2 - space1 - 1);
            std::lock_guard<std::mutex> lock(state->mutex);
            state->status_code = std::stol(status_str);
            // Reset headers on new status line (happens on redirect)
            state->response_headers.clear();
        }
        return size * nitems;
    }
    
    size_t colon_pos = header.find(':');
    if (colon_pos != std::string::npos) {
        std::string key = header.substr(0, colon_pos);
        std::string value = header.substr(colon_pos + 1);
        while (!value.empty() && value.front() == ' ') {
            value.erase(0, 1);
        }
        std::lock_guard<std::mutex> lock(state->mutex);
        state->response_headers[key] = value;
    }
    
    return size * nitems;
}

// Perform curl request (called from reader.read())
static void perform_streaming_fetch(std::shared_ptr<StreamState> state) {
    CURL* curl = curl_easy_init();
    if (!curl) {
        std::lock_guard<std::mutex> lock(state->mutex);
        state->error = true;
        state->error_message = "Failed to initialize curl";
        state->done = true;
        state->cv.notify_one();
        return;
    }
    
    curl_easy_setopt(curl, CURLOPT_URL, state->url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, stream_write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, state.get());
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, stream_header_callback);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, state.get());
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 120L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
    
    if (state->method == "POST") {
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, state->body.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(state->body.size()));
    } else if (state->method == "PUT") {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, state->body.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(state->body.size()));
    } else if (state->method == "DELETE") {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
    } else if (state->method == "PATCH") {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PATCH");
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, state->body.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(state->body.size()));
    }
    
    struct curl_slist* curl_headers = nullptr;
    for (const auto& [key, value] : state->request_headers) {
        std::string header_line = key + ": " + value;
        curl_headers = curl_slist_append(curl_headers, header_line.c_str());
    }
    if (curl_headers) {
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, curl_headers);
    }
    
    CURLcode res = curl_easy_perform(curl);
    
    {
        std::lock_guard<std::mutex> lock(state->mutex);
        if (res == CURLE_OK) {
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &state->status_code);
        } else {
            state->error = true;
            state->error_message = curl_easy_strerror(res);
        }
        state->done = true;
        state->curl_finished = true;
        state->cv.notify_one();
    }
    
    if (curl_headers) {
        curl_slist_free_all(curl_headers);
    }
    curl_easy_cleanup(curl);
}

static void js_readable_stream_finalizer(JSRuntime* /*rt*/, JSValue val) {
    auto* data = static_cast<ReadableStreamData*>(JS_GetOpaque(val, js_readable_stream_class_id));
    delete data;
}

static void js_readable_stream_reader_finalizer(JSRuntime* /*rt*/, JSValue val) {
    auto* data = static_cast<ReadableStreamReaderData*>(JS_GetOpaque(val, js_readable_stream_reader_class_id));
    delete data;
}

static JSClassDef js_readable_stream_class = {
    .class_name = "ReadableStream",
    .finalizer = js_readable_stream_finalizer,
};

static JSClassDef js_readable_stream_reader_class = {
    .class_name = "ReadableStreamDefaultReader",
    .finalizer = js_readable_stream_reader_finalizer,
};

// reader.read() -> Promise<{done: bool, value: Uint8Array}>
static JSValue js_reader_read(JSContext* ctx, JSValueConst this_val,
                              int /*argc*/, JSValueConst* /*argv*/) {
    auto* reader_data = static_cast<ReadableStreamReaderData*>(
        JS_GetOpaque(this_val, js_readable_stream_reader_class_id));
    if (!reader_data || !reader_data->state) {
        return JS_ThrowTypeError(ctx, "Invalid reader");
    }
    
    auto state = reader_data->state;
    
    // Get next chunk - wait if necessary
    std::string chunk;
    bool is_done = false;
    
    {
        std::unique_lock<std::mutex> lock(state->mutex);
        
        // Wait for a chunk or completion
        state->cv.wait(lock, [&state] {
            return !state->chunks.empty() || state->done;
        });
        
        if (!state->chunks.empty()) {
            chunk = std::move(state->chunks.front());
            state->chunks.pop();
        } else if (state->done) {
            is_done = true;
        }
    }
    
    // Create result object {done, value}
    JSValue result = JS_NewObject(ctx);
    
    if (is_done) {
        JS_SetPropertyStr(ctx, result, "done", JS_TRUE);
        JS_SetPropertyStr(ctx, result, "value", JS_UNDEFINED);
    } else {
        JS_SetPropertyStr(ctx, result, "done", JS_FALSE);
        
        // Create Uint8Array from chunk
        // JS_NewTypedArray expects (buffer, byteOffset, length) as arguments
        JSValue array_buffer = JS_NewArrayBufferCopy(ctx, 
            reinterpret_cast<const uint8_t*>(chunk.data()), chunk.size());
        JSValue typed_array_args[] = { 
            array_buffer, 
            JS_NewInt32(ctx, 0),  // byteOffset
            JS_NewInt32(ctx, static_cast<int32_t>(chunk.size()))  // length
        };
        JSValue uint8_array = JS_NewTypedArray(ctx, 3, typed_array_args, JS_TYPED_ARRAY_UINT8);
        JS_FreeValue(ctx, array_buffer);
        JS_FreeValue(ctx, typed_array_args[1]);
        JS_FreeValue(ctx, typed_array_args[2]);
        
        JS_SetPropertyStr(ctx, result, "value", uint8_array);
    }
    
    // Return resolved promise
    JSValue resolving_funcs[2];
    JSValue promise = JS_NewPromiseCapability(ctx, resolving_funcs);
    JS_Call(ctx, resolving_funcs[0], JS_UNDEFINED, 1, &result);
    JS_FreeValue(ctx, result);
    JS_FreeValue(ctx, resolving_funcs[0]);
    JS_FreeValue(ctx, resolving_funcs[1]);
    
    return promise;
}

// stream.getReader() -> ReadableStreamDefaultReader
static JSValue js_stream_get_reader(JSContext* ctx, JSValueConst this_val,
                                    int /*argc*/, JSValueConst* /*argv*/) {
    auto* stream_data = static_cast<ReadableStreamData*>(
        JS_GetOpaque(this_val, js_readable_stream_class_id));
    if (!stream_data) {
        return JS_ThrowTypeError(ctx, "Invalid stream");
    }
    
    if (stream_data->locked) {
        return JS_ThrowTypeError(ctx, "ReadableStream is locked");
    }
    
    stream_data->locked = true;
    
    // Create reader
    JSValue reader = JS_NewObjectClass(ctx, js_readable_stream_reader_class_id);
    auto* reader_data = new ReadableStreamReaderData();
    reader_data->state = stream_data->state;
    reader_data->ctx = ctx;
    JS_SetOpaque(reader, reader_data);
    
    // Add read method to reader
    JS_SetPropertyStr(ctx, reader, "read",
        JS_NewCFunction(ctx, js_reader_read, "read", 0));
    
    return reader;
}

// Create a ReadableStream from a shared state
static JSValue create_readable_stream(JSContext* ctx, std::shared_ptr<StreamState> state) {
    JSValue stream = JS_NewObjectClass(ctx, js_readable_stream_class_id);
    auto* stream_data = new ReadableStreamData();
    stream_data->state = state;
    JS_SetOpaque(stream, stream_data);
    
    // Add getReader method
    JS_SetPropertyStr(ctx, stream, "getReader",
        JS_NewCFunction(ctx, js_stream_get_reader, "getReader", 0));
    
    return stream;
}

// ============================================================================
// TextDecoder implementation for decoding Uint8Array to string
// ============================================================================

static JSClassID js_text_decoder_class_id;

struct TextDecoderData {
    std::string encoding;  // Currently only "utf-8" is supported
};

static void js_text_decoder_finalizer(JSRuntime* /*rt*/, JSValue val) {
    auto* data = static_cast<TextDecoderData*>(JS_GetOpaque(val, js_text_decoder_class_id));
    delete data;
}

static JSClassDef js_text_decoder_class = {
    .class_name = "TextDecoder",
    .finalizer = js_text_decoder_finalizer,
};

// TextDecoder.decode(input) -> string
static JSValue js_text_decoder_decode(JSContext* ctx, JSValueConst this_val,
                                      int argc, JSValueConst* argv) {
    auto* data = static_cast<TextDecoderData*>(JS_GetOpaque(this_val, js_text_decoder_class_id));
    if (!data) {
        return JS_ThrowTypeError(ctx, "Invalid TextDecoder");
    }
    
    if (argc < 1 || JS_IsUndefined(argv[0]) || JS_IsNull(argv[0])) {
        return JS_NewString(ctx, "");
    }
    
    // Get the TypedArray buffer
    size_t byte_offset = 0;
    size_t byte_length = 0;
    size_t bytes_per_element = 0;
    
    JSValue buffer = JS_GetTypedArrayBuffer(ctx, argv[0], &byte_offset, &byte_length, &bytes_per_element);
    if (JS_IsException(buffer)) {
        // Maybe it's an ArrayBuffer directly?
        size_t buffer_size = 0;
        uint8_t* buf = JS_GetArrayBuffer(ctx, &buffer_size, argv[0]);
        if (buf) {
            return JS_NewStringLen(ctx, reinterpret_cast<const char*>(buf), buffer_size);
        }
        return JS_ThrowTypeError(ctx, "TextDecoder.decode: argument must be a TypedArray or ArrayBuffer");
    }
    
    // Get the underlying buffer data
    size_t buffer_size = 0;
    uint8_t* buf = JS_GetArrayBuffer(ctx, &buffer_size, buffer);
    JS_FreeValue(ctx, buffer);
    
    if (!buf) {
        return JS_ThrowTypeError(ctx, "TextDecoder.decode: failed to get array buffer");
    }
    
    // Decode as UTF-8 (the only encoding we support)
    return JS_NewStringLen(ctx, reinterpret_cast<const char*>(buf + byte_offset), byte_length);
}

static JSValue js_text_decoder_constructor(JSContext* ctx, JSValueConst /*new_target*/,
                                           int argc, JSValueConst* argv) {
    JSValue obj = JS_NewObjectClass(ctx, js_text_decoder_class_id);
    if (JS_IsException(obj)) return obj;
    
    auto* data = new TextDecoderData();
    data->encoding = "utf-8";  // Default encoding
    
    if (argc >= 1 && !JS_IsUndefined(argv[0])) {
        const char* enc = JS_ToCString(ctx, argv[0]);
        if (enc) {
            // Normalize encoding name
            std::string enc_str(enc);
            std::transform(enc_str.begin(), enc_str.end(), enc_str.begin(), ::tolower);
            if (enc_str == "utf-8" || enc_str == "utf8") {
                data->encoding = "utf-8";
            }
            // We only support UTF-8 for now
            JS_FreeCString(ctx, enc);
        }
    }
    
    JS_SetOpaque(obj, data);
    
    // Add decode method
    JS_SetPropertyStr(ctx, obj, "decode",
        JS_NewCFunction(ctx, js_text_decoder_decode, "decode", 1));
    
    // Add encoding property
    JS_SetPropertyStr(ctx, obj, "encoding", JS_NewString(ctx, data->encoding.c_str()));
    
    return obj;
}

void setup_text_decoder(JSContext* ctx) {
    // Register TextDecoder class
    JS_NewClassID(&js_text_decoder_class_id);
    JS_NewClass(JS_GetRuntime(ctx), js_text_decoder_class_id, &js_text_decoder_class);
    
    // TextDecoder constructor
    JSValue global = JS_GetGlobalObject(ctx);
    JSValue text_decoder_ctor = JS_NewCFunction2(ctx, js_text_decoder_constructor, 
                                                  "TextDecoder", 1,
                                                  JS_CFUNC_constructor, 0);
    JS_SetPropertyStr(ctx, global, "TextDecoder", text_decoder_ctor);
    JS_FreeValue(ctx, global);
}

// ============================================================================
// Fetch API implementation using libcurl
// ============================================================================

// FetchResponse class for JS
static JSClassID js_fetch_response_class_id;

struct FetchResponseData {
    long status_code = 0;
    std::string body;
    std::unordered_map<std::string, std::string> headers;
    std::shared_ptr<StreamState> stream_state;  // For streaming responses
    bool is_streaming = false;
    bool body_consumed = false;  // Track if body has been fully read
};

static void js_fetch_response_finalizer(JSRuntime* /*rt*/, JSValue val) {
    auto* data = static_cast<FetchResponseData*>(JS_GetOpaque(val, js_fetch_response_class_id));
    delete data;
}

static JSClassDef js_fetch_response_class = {
    .class_name = "FetchResponse",
    .finalizer = js_fetch_response_finalizer,
};

// Helper to consume streaming body into the body string
static void consume_stream_body(FetchResponseData* data) {
    if (!data || data->body_consumed || !data->stream_state) {
        return;
    }
    
    auto& state = data->stream_state;
    
    // Wait for all data to arrive
    {
        std::unique_lock<std::mutex> lock(state->mutex);
        state->cv.wait(lock, [&state] {
            return state->done;
        });
        
        // Collect all chunks into body
        while (!state->chunks.empty()) {
            data->body += state->chunks.front();
            state->chunks.pop();
        }
    }
    
    data->body_consumed = true;
}

static JSValue js_fetch_response_json(JSContext* ctx, JSValueConst this_val,
                                      int /*argc*/, JSValueConst* /*argv*/) {
    auto* data = static_cast<FetchResponseData*>(JS_GetOpaque(this_val, js_fetch_response_class_id));
    if (!data) return JS_UNDEFINED;
    
    // Consume stream if needed
    consume_stream_body(data);
    
    return JS_ParseJSON(ctx, data->body.c_str(), data->body.size(), "<fetch-json>");
}

static JSValue js_fetch_response_text(JSContext* ctx, JSValueConst this_val,
                                      int /*argc*/, JSValueConst* /*argv*/) {
    auto* data = static_cast<FetchResponseData*>(JS_GetOpaque(this_val, js_fetch_response_class_id));
    if (!data) return JS_UNDEFINED;
    
    // Consume stream if needed
    consume_stream_body(data);
    
    return JS_NewString(ctx, data->body.c_str());
}

static JSValue js_fetch_response_get_status(JSContext* ctx, JSValueConst this_val) {
    auto* data = static_cast<FetchResponseData*>(JS_GetOpaque(this_val, js_fetch_response_class_id));
    if (!data) return JS_UNDEFINED;
    return JS_NewInt32(ctx, static_cast<int>(data->status_code));
}

static JSValue js_fetch_response_get_ok(JSContext* ctx, JSValueConst this_val) {
    auto* data = static_cast<FetchResponseData*>(JS_GetOpaque(this_val, js_fetch_response_class_id));
    if (!data) return JS_UNDEFINED;
    return JS_NewBool(ctx, data->status_code >= 200 && data->status_code < 300);
}

static JSValue js_fetch_response_get_body(JSContext* ctx, JSValueConst this_val) {
    auto* data = static_cast<FetchResponseData*>(JS_GetOpaque(this_val, js_fetch_response_class_id));
    if (!data) return JS_UNDEFINED;
    
    // If streaming, return ReadableStream
    if (data->stream_state) {
        return create_readable_stream(ctx, data->stream_state);
    }
    
    // Otherwise return body as string (legacy behavior)
    return JS_NewString(ctx, data->body.c_str());
}

static JSValue js_fetch_response_get_headers(JSContext* ctx, JSValueConst this_val) {
    auto* data = static_cast<FetchResponseData*>(JS_GetOpaque(this_val, js_fetch_response_class_id));
    if (!data) return JS_UNDEFINED;
    
    // Create a Headers instance using the global Headers class
    JSValue global = JS_GetGlobalObject(ctx);
    JSValue headers_ctor = JS_GetPropertyStr(ctx, global, "Headers");
    JS_FreeValue(ctx, global);
    
    if (JS_IsUndefined(headers_ctor)) {
        // Fallback to plain object if Headers class not available
        JSValue headers = JS_NewObject(ctx);
        for (const auto& [key, value] : data->headers) {
            JS_SetPropertyStr(ctx, headers, key.c_str(), JS_NewString(ctx, value.c_str()));
        }
        return headers;
    }
    
    // Create new Headers() instance
    JSValue headers_obj = JS_CallConstructor(ctx, headers_ctor, 0, nullptr);
    JS_FreeValue(ctx, headers_ctor);
    
    if (JS_IsException(headers_obj)) {
        return headers_obj;
    }
    
    // Call headers.append(key, value) for each header
    JSValue append_func = JS_GetPropertyStr(ctx, headers_obj, "append");
    for (const auto& [key, value] : data->headers) {
        JSValue args[2] = {
            JS_NewString(ctx, key.c_str()),
            JS_NewString(ctx, value.c_str())
        };
        JSValue result = JS_Call(ctx, append_func, headers_obj, 2, args);
        JS_FreeValue(ctx, args[0]);
        JS_FreeValue(ctx, args[1]);
        JS_FreeValue(ctx, result);
    }
    JS_FreeValue(ctx, append_func);
    
    return headers_obj;
}

static JSValue js_fetch_response_arraybuffer(JSContext* ctx, JSValueConst this_val,
                                             int /*argc*/, JSValueConst* /*argv*/) {
    auto* data = static_cast<FetchResponseData*>(JS_GetOpaque(this_val, js_fetch_response_class_id));
    if (!data) return JS_UNDEFINED;
    
    // Consume stream if needed
    consume_stream_body(data);
    
    // Create ArrayBuffer from body data
    size_t len = data->body.size();
    JSValue arraybuf = JS_NewArrayBufferCopy(ctx, 
        reinterpret_cast<const uint8_t*>(data->body.data()), len);
    return arraybuf;
}

static JSValue js_fetch_response_get_bodyUsed(JSContext* ctx, JSValueConst this_val) {
    auto* data = static_cast<FetchResponseData*>(JS_GetOpaque(this_val, js_fetch_response_class_id));
    if (!data) return JS_UNDEFINED;
    return JS_NewBool(ctx, data->body_consumed);
}

static const JSCFunctionListEntry js_fetch_response_proto_funcs[] = {
    JS_CGETSET_DEF("status", js_fetch_response_get_status, nullptr),
    JS_CGETSET_DEF("ok", js_fetch_response_get_ok, nullptr),
    JS_CGETSET_DEF("body", js_fetch_response_get_body, nullptr),
    JS_CGETSET_DEF("bodyUsed", js_fetch_response_get_bodyUsed, nullptr),
    JS_CGETSET_DEF("headers", js_fetch_response_get_headers, nullptr),
    JS_CFUNC_DEF("json", 0, js_fetch_response_json),
    JS_CFUNC_DEF("text", 0, js_fetch_response_text),
    JS_CFUNC_DEF("arrayBuffer", 0, js_fetch_response_arraybuffer),
};

namespace {

struct FetchResponse {
    long status_code = 0;
    std::string body;
    std::unordered_map<std::string, std::string> headers;
};

size_t curl_write_callback(char* ptr, size_t size, size_t nmemb, void* userdata) {
    auto* response = static_cast<std::string*>(userdata);
    response->append(ptr, size * nmemb);
    return size * nmemb;
}

size_t curl_header_callback(char* buffer, size_t size, size_t nitems, void* userdata) {
    auto* headers = static_cast<std::unordered_map<std::string, std::string>*>(userdata);
    std::string header(buffer, size * nitems);
    
    // Remove trailing \r\n
    while (!header.empty() && (header.back() == '\r' || header.back() == '\n')) {
        header.pop_back();
    }
    
    // Parse "Key: Value" format
    size_t colon_pos = header.find(':');
    if (colon_pos != std::string::npos) {
        std::string key = header.substr(0, colon_pos);
        std::string value = header.substr(colon_pos + 1);
        // Trim leading whitespace from value
        while (!value.empty() && value.front() == ' ') {
            value.erase(0, 1);
        }
        (*headers)[key] = value;
    }
    
    return size * nitems;
}

FetchResponse perform_fetch(const std::string& url, const std::string& method,
                           const std::unordered_map<std::string, std::string>& headers,
                           const std::string& body) {
    FetchResponse response;
    
    CURL* curl = curl_easy_init();
    if (!curl) {
        response.status_code = 0;
        return response;
    }
    
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response.body);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, curl_header_callback);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &response.headers);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
    
    // Set method
    if (method == "POST") {
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(body.size()));
    } else if (method == "PUT") {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(body.size()));
    } else if (method == "DELETE") {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
    } else if (method == "PATCH") {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PATCH");
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(body.size()));
    } else if (method == "HEAD") {
        curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    }
    // GET is the default
    
    // Set headers
    struct curl_slist* curl_headers = nullptr;
    for (const auto& [key, value] : headers) {
        std::string header_line = key + ": " + value;
        curl_headers = curl_slist_append(curl_headers, header_line.c_str());
    }
    if (curl_headers) {
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, curl_headers);
    }
    
    // Perform request
    CURLcode res = curl_easy_perform(curl);
    
    if (res == CURLE_OK) {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response.status_code);
    } else {
        response.status_code = 0;
        response.body = curl_easy_strerror(res);
    }
    
    if (curl_headers) {
        curl_slist_free_all(curl_headers);
    }
    curl_easy_cleanup(curl);
    
    return response;
}

}  // anonymous namespace

// fetch(url, options?) -> Promise<Response>
static JSValue js_fetch(JSContext* ctx, JSValueConst /*this_val*/,
                        int argc, JSValueConst* argv)
{
    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "fetch requires at least 1 argument (url)");
    }
    
    std::string url;
    std::string method = "GET";
    std::string body;
    std::unordered_map<std::string, std::string> headers;
    
    // Check if first argument is a Request object
    if (JS_IsObject(argv[0])) {
        // Check if it has a 'url' property (Request object)
        JSValue url_prop = JS_GetPropertyStr(ctx, argv[0], "url");
        if (!JS_IsUndefined(url_prop)) {
            const char* url_str = JS_ToCString(ctx, url_prop);
            if (url_str) {
                url = url_str;
                JS_FreeCString(ctx, url_str);
            }
            JS_FreeValue(ctx, url_prop);
            
            // Get method from Request
            JSValue method_prop = JS_GetPropertyStr(ctx, argv[0], "method");
            if (!JS_IsUndefined(method_prop)) {
                const char* method_str = JS_ToCString(ctx, method_prop);
                if (method_str) {
                    method = method_str;
                    JS_FreeCString(ctx, method_str);
                }
            }
            JS_FreeValue(ctx, method_prop);
            
            // Get headers from Request
            JSValue headers_prop = JS_GetPropertyStr(ctx, argv[0], "headers");
            if (JS_IsObject(headers_prop)) {
                // Call forEach on Headers object to extract headers
                JSValue forEach = JS_GetPropertyStr(ctx, headers_prop, "forEach");
                if (JS_IsFunction(ctx, forEach)) {
                    // Create a callback that collects headers
                    // For simplicity, try to get common headers or iterate
                    JSValue entries = JS_GetPropertyStr(ctx, headers_prop, "entries");
                    if (JS_IsFunction(ctx, entries)) {
                        JSValue iter = JS_Call(ctx, entries, headers_prop, 0, nullptr);
                        if (!JS_IsException(iter)) {
                            JSValue next_fn = JS_GetPropertyStr(ctx, iter, "next");
                            if (JS_IsFunction(ctx, next_fn)) {
                                while (true) {
                                    JSValue result = JS_Call(ctx, next_fn, iter, 0, nullptr);
                                    if (JS_IsException(result)) break;
                                    
                                    JSValue done = JS_GetPropertyStr(ctx, result, "done");
                                    bool is_done = JS_ToBool(ctx, done);
                                    JS_FreeValue(ctx, done);
                                    
                                    if (is_done) {
                                        JS_FreeValue(ctx, result);
                                        break;
                                    }
                                    
                                    JSValue value = JS_GetPropertyStr(ctx, result, "value");
                                    if (JS_IsArray(ctx, value)) {
                                        JSValue key_val = JS_GetPropertyUint32(ctx, value, 0);
                                        JSValue val_val = JS_GetPropertyUint32(ctx, value, 1);
                                        const char* key = JS_ToCString(ctx, key_val);
                                        const char* val = JS_ToCString(ctx, val_val);
                                        if (key && val) {
                                            headers[key] = val;
                                        }
                                        if (key) JS_FreeCString(ctx, key);
                                        if (val) JS_FreeCString(ctx, val);
                                        JS_FreeValue(ctx, key_val);
                                        JS_FreeValue(ctx, val_val);
                                    }
                                    JS_FreeValue(ctx, value);
                                    JS_FreeValue(ctx, result);
                                }
                            }
                            JS_FreeValue(ctx, next_fn);
                            JS_FreeValue(ctx, iter);
                        }
                        JS_FreeValue(ctx, entries);
                    }
                }
                JS_FreeValue(ctx, forEach);
            }
            JS_FreeValue(ctx, headers_prop);
            
            // Get body from Request
            JSValue body_prop = JS_GetPropertyStr(ctx, argv[0], "body");
            if (!JS_IsUndefined(body_prop) && !JS_IsNull(body_prop)) {
                const char* body_str = JS_ToCString(ctx, body_prop);
                if (body_str) {
                    body = body_str;
                    JS_FreeCString(ctx, body_str);
                }
            }
            JS_FreeValue(ctx, body_prop);
        } else {
            JS_FreeValue(ctx, url_prop);
            // Not a Request object, treat as URL string
            const char* url_str = JS_ToCString(ctx, argv[0]);
            if (!url_str) {
                return JS_ThrowTypeError(ctx, "fetch: invalid URL");
            }
            url = url_str;
            JS_FreeCString(ctx, url_str);
        }
    } else {
        // Simple string URL
        const char* url_str = JS_ToCString(ctx, argv[0]);
        if (!url_str) {
            return JS_ThrowTypeError(ctx, "fetch: invalid URL");
        }
        url = url_str;
        JS_FreeCString(ctx, url_str);
    }
    
    // Parse options (second argument overrides Request properties)
    if (argc >= 2 && JS_IsObject(argv[1])) {
        JSValue options = argv[1];
        
        // Get method
        JSValue method_val = JS_GetPropertyStr(ctx, options, "method");
        if (!JS_IsUndefined(method_val)) {
            const char* method_str = JS_ToCString(ctx, method_val);
            if (method_str) {
                method = method_str;
                JS_FreeCString(ctx, method_str);
            }
        }
        JS_FreeValue(ctx, method_val);
        
        // Get body
        JSValue body_val = JS_GetPropertyStr(ctx, options, "body");
        if (!JS_IsUndefined(body_val)) {
            const char* body_str = JS_ToCString(ctx, body_val);
            if (body_str) {
                body = body_str;
                JS_FreeCString(ctx, body_str);
            }
        }
        JS_FreeValue(ctx, body_val);
        
        // Get headers
        JSValue headers_val = JS_GetPropertyStr(ctx, options, "headers");
        if (JS_IsObject(headers_val)) {
            JSPropertyEnum* props = nullptr;
            uint32_t prop_count = 0;
            
            if (JS_GetOwnPropertyNames(ctx, &props, &prop_count, headers_val,
                                       JS_GPN_STRING_MASK | JS_GPN_ENUM_ONLY) == 0) {
                for (uint32_t i = 0; i < prop_count; i++) {
                    const char* key = JS_AtomToCString(ctx, props[i].atom);
                    if (key) {
                        JSValue val = JS_GetProperty(ctx, headers_val, props[i].atom);
                        const char* val_str = JS_ToCString(ctx, val);
                        if (val_str) {
                            headers[key] = val_str;
                            JS_FreeCString(ctx, val_str);
                        }
                        JS_FreeValue(ctx, val);
                        JS_FreeCString(ctx, key);
                    }
                }
                
                for (uint32_t i = 0; i < prop_count; i++) {
                    JS_FreeAtom(ctx, props[i].atom);
                }
                js_free(ctx, props);
            }
        }
        JS_FreeValue(ctx, headers_val);
    }
    
    // Create StreamState for streaming
    auto stream_state = std::make_shared<StreamState>();
    stream_state->url = url;
    stream_state->method = method;
    stream_state->body = body;
    stream_state->request_headers = headers;
    stream_state->curl_started = true;
    
    // Start curl in background thread
    std::thread([stream_state]() {
        perform_streaming_fetch(stream_state);
    }).detach();
    
    // Create promise that will be resolved when headers are received
    JSValue resolving_funcs[2];
    JSValue promise = JS_NewPromiseCapability(ctx, resolving_funcs);
    if (JS_IsException(promise)) {
        return promise;
    }
    
    // Add to pending fetches for async processing
    auto* fetch_state = get_fetch_state(ctx);
    if (fetch_state) {
        PendingFetch pending;
        pending.stream_state = stream_state;
        pending.resolve_func = JS_DupValue(ctx, resolving_funcs[0]);
        pending.reject_func = JS_DupValue(ctx, resolving_funcs[1]);
        pending.ctx = ctx;
        fetch_state->pending.push_back(std::move(pending));
    }
    
    JS_FreeValue(ctx, resolving_funcs[0]);
    JS_FreeValue(ctx, resolving_funcs[1]);
    
    return promise;
}

// Streaming fetch context
struct StreamingFetchCtx {
    JSContext* ctx;
    JSValue callback;
    std::string line_buffer;
};

size_t streaming_curl_write_callback(char* ptr, size_t size, size_t nmemb, void* userdata) {
    auto* sfc = static_cast<StreamingFetchCtx*>(userdata);
    size_t total = size * nmemb;
    
    // Append data to line buffer
    sfc->line_buffer.append(ptr, total);
    
    // Process complete lines
    size_t pos;
    while ((pos = sfc->line_buffer.find('\n')) != std::string::npos) {
        std::string line = sfc->line_buffer.substr(0, pos);
        sfc->line_buffer.erase(0, pos + 1);
        
        // Remove \r if present
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        
        // Call JS callback with the line
        JSValue line_val = JS_NewString(sfc->ctx, line.c_str());
        JSValue args[] = { line_val };
        JSValue result = JS_Call(sfc->ctx, sfc->callback, JS_UNDEFINED, 1, args);
        JS_FreeValue(sfc->ctx, line_val);
        
        if (JS_IsException(result)) {
            JS_FreeValue(sfc->ctx, result);
            return 0;  // Abort transfer
        }
        JS_FreeValue(sfc->ctx, result);
    }
    
    return total;
}

// fetchStream(url, options, onChunk) - streaming fetch that calls onChunk for each line
static JSValue js_fetch_stream(JSContext* ctx, JSValueConst /*this_val*/,
                               int argc, JSValueConst* argv)
{
    if (argc < 3) {
        return JS_ThrowTypeError(ctx, "fetchStream requires 3 arguments (url, options, onChunk)");
    }
    
    if (!JS_IsFunction(ctx, argv[2])) {
        return JS_ThrowTypeError(ctx, "fetchStream: third argument must be a callback function");
    }
    
    // Get URL
    const char* url_str = JS_ToCString(ctx, argv[0]);
    if (!url_str) {
        return JS_ThrowTypeError(ctx, "fetchStream: invalid URL");
    }
    std::string url(url_str);
    JS_FreeCString(ctx, url_str);
    
    // Parse options
    std::string method = "GET";
    std::string body;
    std::unordered_map<std::string, std::string> headers;
    
    if (JS_IsObject(argv[1])) {
        JSValue options = argv[1];
        
        JSValue method_val = JS_GetPropertyStr(ctx, options, "method");
        if (!JS_IsUndefined(method_val)) {
            const char* method_str = JS_ToCString(ctx, method_val);
            if (method_str) {
                method = method_str;
                JS_FreeCString(ctx, method_str);
            }
        }
        JS_FreeValue(ctx, method_val);
        
        JSValue body_val = JS_GetPropertyStr(ctx, options, "body");
        if (!JS_IsUndefined(body_val)) {
            const char* body_str = JS_ToCString(ctx, body_val);
            if (body_str) {
                body = body_str;
                JS_FreeCString(ctx, body_str);
            }
        }
        JS_FreeValue(ctx, body_val);
        
        JSValue headers_val = JS_GetPropertyStr(ctx, options, "headers");
        if (JS_IsObject(headers_val)) {
            JSPropertyEnum* props = nullptr;
            uint32_t prop_count = 0;
            if (JS_GetOwnPropertyNames(ctx, &props, &prop_count, headers_val,
                                       JS_GPN_STRING_MASK | JS_GPN_ENUM_ONLY) == 0) {
                for (uint32_t i = 0; i < prop_count; i++) {
                    const char* key = JS_AtomToCString(ctx, props[i].atom);
                    if (key) {
                        JSValue val = JS_GetProperty(ctx, headers_val, props[i].atom);
                        const char* val_str = JS_ToCString(ctx, val);
                        if (val_str) {
                            headers[key] = val_str;
                            JS_FreeCString(ctx, val_str);
                        }
                        JS_FreeValue(ctx, val);
                        JS_FreeCString(ctx, key);
                    }
                }
                for (uint32_t i = 0; i < prop_count; i++) {
                    JS_FreeAtom(ctx, props[i].atom);
                }
                js_free(ctx, props);
            }
        }
        JS_FreeValue(ctx, headers_val);
    }
    
    // Set up streaming context
    StreamingFetchCtx sfc;
    sfc.ctx = ctx;
    sfc.callback = argv[2];
    
    // Perform streaming fetch
    CURL* curl = curl_easy_init();
    if (!curl) {
        return JS_ThrowInternalError(ctx, "fetchStream: failed to initialize curl");
    }
    
    std::unordered_map<std::string, std::string> response_headers;
    
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, streaming_curl_write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &sfc);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, curl_header_callback);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &response_headers);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 120L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
    
    if (method == "POST") {
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(body.size()));
    }
    
    struct curl_slist* curl_headers = nullptr;
    for (const auto& [key, value] : headers) {
        std::string header_line = key + ": " + value;
        curl_headers = curl_slist_append(curl_headers, header_line.c_str());
    }
    if (curl_headers) {
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, curl_headers);
    }
    
    CURLcode res = curl_easy_perform(curl);
    
    long status_code = 0;
    if (res == CURLE_OK) {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status_code);
    }
    
    // Process any remaining data in buffer
    if (!sfc.line_buffer.empty()) {
        JSValue line_val = JS_NewString(ctx, sfc.line_buffer.c_str());
        JSValue args[] = { line_val };
        JSValue result = JS_Call(ctx, sfc.callback, JS_UNDEFINED, 1, args);
        JS_FreeValue(ctx, line_val);
        JS_FreeValue(ctx, result);
    }
    
    if (curl_headers) {
        curl_slist_free_all(curl_headers);
    }
    curl_easy_cleanup(curl);
    
    // Return status
    JSValue result = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, result, "status", JS_NewInt32(ctx, static_cast<int>(status_code)));
    JS_SetPropertyStr(ctx, result, "ok", JS_NewBool(ctx, status_code >= 200 && status_code < 300));
    
    if (res != CURLE_OK) {
        JS_SetPropertyStr(ctx, result, "error", JS_NewString(ctx, curl_easy_strerror(res)));
    }
    
    return result;
}

void setup_fetch(JSContext* ctx) {
    // Register FetchResponse class
    JS_NewClassID(&js_fetch_response_class_id);
    JS_NewClass(JS_GetRuntime(ctx), js_fetch_response_class_id, &js_fetch_response_class);
    
    JSValue proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, proto, js_fetch_response_proto_funcs,
                               sizeof(js_fetch_response_proto_funcs) / sizeof(js_fetch_response_proto_funcs[0]));
    JS_SetClassProto(ctx, js_fetch_response_class_id, proto);
    
    // Register ReadableStream class
    JS_NewClassID(&js_readable_stream_class_id);
    JS_NewClass(JS_GetRuntime(ctx), js_readable_stream_class_id, &js_readable_stream_class);
    
    // Register ReadableStreamDefaultReader class
    JS_NewClassID(&js_readable_stream_reader_class_id);
    JS_NewClass(JS_GetRuntime(ctx), js_readable_stream_reader_class_id, &js_readable_stream_reader_class);
    
    // Register FetchState class for async fetch tracking
    if (!fetch_class_registered) {
        JS_NewClassID(&js_fetch_state_class_id);
        fetch_class_registered = true;
    }
    JS_NewClass(JS_GetRuntime(ctx), js_fetch_state_class_id, &js_fetch_state_class);
    
    // Create and store fetch state on global object
    JSValue fetch_state_obj = JS_NewObjectClass(ctx, static_cast<int>(js_fetch_state_class_id));
    auto* fetch_state = new FetchState{};
    JS_SetOpaque(fetch_state_obj, fetch_state);
    
    // Register fetch functions
    JSValue global = JS_GetGlobalObject(ctx);
    JS_SetPropertyStr(ctx, global, "__fetch_state__", fetch_state_obj);
    JS_SetPropertyStr(ctx, global, "fetch",
        JS_NewCFunction(ctx, js_fetch, "fetch", 2));
    JS_SetPropertyStr(ctx, global, "fetchStream",
        JS_NewCFunction(ctx, js_fetch_stream, "fetchStream", 3));
    JS_FreeValue(ctx, global);
}

// Process pending fetch operations - called from event loop
bool process_pending_fetches(JSContext* ctx) {
    auto* state = get_fetch_state(ctx);
    if (!state || state->pending.empty()) {
        return false;
    }
    
    bool processed_any = false;
    
    // Process each pending fetch
    auto it = state->pending.begin();
    while (it != state->pending.end()) {
        auto& pending = *it;
        auto& stream_state = pending.stream_state;
        
        bool ready = false;
        bool has_error = false;
        
        {
            std::lock_guard<std::mutex> lock(stream_state->mutex);
            ready = stream_state->headers_received || stream_state->done;
            has_error = stream_state->error;
        }
        
        if (ready || has_error) {
            // Resolve or reject the promise
            if (has_error) {
                JSValue error = JS_NewError(ctx);
                JS_SetPropertyStr(ctx, error, "message", 
                    JS_NewString(ctx, stream_state->error_message.c_str()));
                JS_Call(ctx, pending.reject_func, JS_UNDEFINED, 1, &error);
                JS_FreeValue(ctx, error);
            } else {
                // Create response object
                JSValue response_obj = JS_NewObjectClass(ctx, static_cast<int>(js_fetch_response_class_id));
                auto* response_data = new FetchResponseData();
                response_data->status_code = stream_state->status_code;
                response_data->stream_state = stream_state;
                response_data->is_streaming = true;
                response_data->headers = stream_state->response_headers;
                JS_SetOpaque(response_obj, response_data);
                
                JS_Call(ctx, pending.resolve_func, JS_UNDEFINED, 1, &response_obj);
                JS_FreeValue(ctx, response_obj);
            }
            
            // Cleanup
            JS_FreeValue(ctx, pending.resolve_func);
            JS_FreeValue(ctx, pending.reject_func);
            it = state->pending.erase(it);
            processed_any = true;
        } else {
            ++it;
        }
    }
    
    return processed_any;
}

// Check if there are pending fetch operations
bool has_pending_fetches(JSContext* ctx) {
    auto* state = get_fetch_state(ctx);
    return state && !state->pending.empty();
}

// Cleanup pending fetches when context is destroyed
void cleanup_pending_fetches(JSContext* ctx) {
    auto* state = get_fetch_state(ctx);
    if (state) {
        for (auto& pending : state->pending) {
            JS_FreeValue(ctx, pending.resolve_func);
            JS_FreeValue(ctx, pending.reject_func);
        }
        state->pending.clear();
    }
}

// ============================================================================
// Timer API implementation (setTimeout / clearTimeout)
// ============================================================================

namespace {

struct Timer {
    int32_t id;
    std::chrono::steady_clock::time_point fire_time;
    JSValue callback;
    bool cancelled = false;
};

// Per-context timer storage - stored as opaque data on a global object
struct TimerState {
    std::map<int32_t, Timer> timers;
    int32_t next_id = 1;
};

static JSClassID js_timer_state_class_id;

static void js_timer_state_finalizer(JSRuntime* /*rt*/, JSValue val) {
    auto* state = static_cast<TimerState*>(JS_GetOpaque(val, js_timer_state_class_id));
    // Note: Timer callbacks should already be freed by cleanup_timers
    delete state;
}

static JSClassDef js_timer_state_class = {
    .class_name = "TimerState",
    .finalizer = js_timer_state_finalizer,
};

static bool timer_class_registered = false;

TimerState* get_timer_state(JSContext* ctx) {
    JSValue global = JS_GetGlobalObject(ctx);
    JSValue state_val = JS_GetPropertyStr(ctx, global, "__timer_state__");
    JS_FreeValue(ctx, global);
    
    if (JS_IsUndefined(state_val)) {
        return nullptr;
    }
    
    auto* state = static_cast<TimerState*>(JS_GetOpaque(state_val, js_timer_state_class_id));
    JS_FreeValue(ctx, state_val);
    return state;
}

}  // anonymous namespace

static JSValue js_setTimeout(JSContext* ctx, JSValueConst /*this_val*/,
                             int argc, JSValueConst* argv)
{
    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "setTimeout requires at least 1 argument");
    }
    
    // First argument: callback function
    if (!JS_IsFunction(ctx, argv[0])) {
        return JS_ThrowTypeError(ctx, "setTimeout: first argument must be a function");
    }
    
    // Second argument: delay in milliseconds (default 0)
    int32_t delay_ms = 0;
    if (argc >= 2) {
        if (JS_ToInt32(ctx, &delay_ms, argv[1])) {
            return JS_EXCEPTION;
        }
        if (delay_ms < 0) delay_ms = 0;
    }
    
    auto* state = get_timer_state(ctx);
    if (!state) {
        return JS_ThrowInternalError(ctx, "Timer state not initialized");
    }
    
    Timer timer;
    timer.id = state->next_id++;
    timer.fire_time = std::chrono::steady_clock::now() + std::chrono::milliseconds(delay_ms);
    timer.callback = JS_DupValue(ctx, argv[0]);
    
    state->timers[timer.id] = timer;
    
    return JS_NewInt32(ctx, timer.id);
}

static JSValue js_clearTimeout(JSContext* ctx, JSValueConst /*this_val*/,
                               int argc, JSValueConst* argv)
{
    if (argc < 1) {
        return JS_UNDEFINED;
    }
    
    int32_t timer_id;
    if (JS_ToInt32(ctx, &timer_id, argv[0])) {
        return JS_UNDEFINED;
    }
    
    auto* state = get_timer_state(ctx);
    if (!state) {
        return JS_UNDEFINED;
    }
    auto it = state->timers.find(timer_id);
    if (it != state->timers.end()) {
        it->second.cancelled = true;
    }
    
    return JS_UNDEFINED;
}

void setup_timers(JSContext* ctx) {
    // Register the timer state class (once per runtime)
    if (!timer_class_registered) {
        JS_NewClassID(&js_timer_state_class_id);
        timer_class_registered = true;
    }
    JS_NewClass(JS_GetRuntime(ctx), js_timer_state_class_id, &js_timer_state_class);
    
    // Create and store timer state on global object
    JSValue state_obj = JS_NewObjectClass(ctx, static_cast<int>(js_timer_state_class_id));
    auto* state = new TimerState{};
    JS_SetOpaque(state_obj, state);
    
    JSValue global = JS_GetGlobalObject(ctx);
    JS_SetPropertyStr(ctx, global, "__timer_state__", state_obj);
    JS_SetPropertyStr(ctx, global, "setTimeout",
        JS_NewCFunction(ctx, js_setTimeout, "setTimeout", 2));
    JS_SetPropertyStr(ctx, global, "clearTimeout",
        JS_NewCFunction(ctx, js_clearTimeout, "clearTimeout", 1));
    JS_FreeValue(ctx, global);
}

bool process_timers(JSContext* ctx) {
    auto* state = get_timer_state(ctx);
    if (!state) {
        return false;
    }
    
    auto now = std::chrono::steady_clock::now();
    bool processed_any = false;
    
    // Collect expired timers
    std::vector<int32_t> expired_ids;
    for (auto& [id, timer] : state->timers) {
        if (!timer.cancelled && now >= timer.fire_time) {
            expired_ids.push_back(id);
        }
    }
    
    // Fire expired timers
    for (int32_t id : expired_ids) {
        auto timer_it = state->timers.find(id);
        if (timer_it == state->timers.end()) continue;
        
        Timer& timer = timer_it->second;
        if (timer.cancelled) {
            JS_FreeValue(ctx, timer.callback);
            state->timers.erase(timer_it);
            continue;
        }
        
        // Call the callback
        JSValue ret = JS_Call(ctx, timer.callback, JS_UNDEFINED, 0, nullptr);
        if (JS_IsException(ret)) {
            // Log but don't propagate - timer callbacks shouldn't break the main flow
            JSValue exc = JS_GetException(ctx);
            const char* str = JS_ToCString(ctx, exc);
            if (str) {
                std::cerr << "Timer callback error: " << str << "\n";
                JS_FreeCString(ctx, str);
            }
            JS_FreeValue(ctx, exc);
        }
        JS_FreeValue(ctx, ret);
        
        // Cleanup
        JS_FreeValue(ctx, timer.callback);
        state->timers.erase(timer_it);
        processed_any = true;
    }
    
    return processed_any;
}

bool has_pending_timers(JSContext* ctx) {
    auto* state = get_timer_state(ctx);
    if (!state) {
        return false;
    }
    
    for (const auto& [id, timer] : state->timers) {
        if (!timer.cancelled) {
            return true;
        }
    }
    return false;
}

// Cleanup timer state when context is destroyed (called from JsContext destructor)
void cleanup_timers(JSContext* ctx) {
    auto* state = get_timer_state(ctx);
    if (state) {
        for (auto& [id, timer] : state->timers) {
            JS_FreeValue(ctx, timer.callback);
        }
        state->timers.clear();
    }
    // Note: The TimerState itself will be freed by js_timer_state_finalizer
    // when the context is freed
}

// ============================================================================
// KV Store module - import { kv } from 'quickw'
// ============================================================================

// kv.get(key) -> string | null
static JSValue js_kv_get(JSContext* ctx, JSValueConst /*this_val*/,
                         int argc, JSValueConst* argv) {
    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "kv.get requires 1 argument (key)");
    }
    
    const char* key = JS_ToCString(ctx, argv[0]);
    if (!key) {
        return JS_ThrowTypeError(ctx, "kv.get: key must be a string");
    }
    
    auto result = KvStore::instance().get(key);
    JS_FreeCString(ctx, key);
    
    if (result) {
        return JS_NewString(ctx, result->c_str());
    }
    return JS_NULL;
}

// kv.set(key, value, ttl?) -> void (throws if key/value too large)
static JSValue js_kv_set(JSContext* ctx, JSValueConst /*this_val*/,
                         int argc, JSValueConst* argv) {
    if (argc < 2) {
        return JS_ThrowTypeError(ctx, "kv.set requires at least 2 arguments (key, value)");
    }
    
    const char* key = JS_ToCString(ctx, argv[0]);
    if (!key) {
        return JS_ThrowTypeError(ctx, "kv.set: key must be a string");
    }
    
    const char* value = JS_ToCString(ctx, argv[1]);
    if (!value) {
        JS_FreeCString(ctx, key);
        return JS_ThrowTypeError(ctx, "kv.set: value must be a string");
    }
    
    uint64_t ttl_ms = 0;
    if (argc >= 3 && !JS_IsUndefined(argv[2]) && !JS_IsNull(argv[2])) {
        int64_t ttl;
        if (JS_ToInt64(ctx, &ttl, argv[2])) {
            JS_FreeCString(ctx, key);
            JS_FreeCString(ctx, value);
            return JS_EXCEPTION;
        }
        if (ttl > 0) {
            ttl_ms = static_cast<uint64_t>(ttl);
        }
    }
    
    bool success = KvStore::instance().set(key, value, ttl_ms);
    
    JS_FreeCString(ctx, key);
    JS_FreeCString(ctx, value);
    
    if (!success) {
        return JS_ThrowRangeError(ctx, "kv.set: key exceeds 128 bytes or value exceeds 1024 bytes");
    }
    
    return JS_UNDEFINED;
}

// kv.del(key) -> boolean
static JSValue js_kv_del(JSContext* ctx, JSValueConst /*this_val*/,
                         int argc, JSValueConst* argv) {
    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "kv.del requires 1 argument (key)");
    }
    
    const char* key = JS_ToCString(ctx, argv[0]);
    if (!key) {
        return JS_ThrowTypeError(ctx, "kv.del: key must be a string");
    }
    
    bool deleted = KvStore::instance().del(key);
    JS_FreeCString(ctx, key);
    
    return JS_NewBool(ctx, deleted);
}

// kv.exists(key) -> boolean
static JSValue js_kv_exists(JSContext* ctx, JSValueConst /*this_val*/,
                            int argc, JSValueConst* argv) {
    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "kv.exists requires 1 argument (key)");
    }
    
    const char* key = JS_ToCString(ctx, argv[0]);
    if (!key) {
        return JS_ThrowTypeError(ctx, "kv.exists: key must be a string");
    }
    
    bool exists = KvStore::instance().exists(key);
    JS_FreeCString(ctx, key);
    
    return JS_NewBool(ctx, exists);
}

// kv.ttl(key) -> number | null (remaining TTL in ms)
static JSValue js_kv_ttl(JSContext* ctx, JSValueConst /*this_val*/,
                         int argc, JSValueConst* argv) {
    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "kv.ttl requires 1 argument (key)");
    }
    
    const char* key = JS_ToCString(ctx, argv[0]);
    if (!key) {
        return JS_ThrowTypeError(ctx, "kv.ttl: key must be a string");
    }
    
    auto result = KvStore::instance().ttl(key);
    JS_FreeCString(ctx, key);
    
    if (result) {
        return JS_NewInt64(ctx, static_cast<int64_t>(*result));
    }
    return JS_NULL;
}

// kv.scan(prefix, limit?) -> string[]
static JSValue js_kv_scan(JSContext* ctx, JSValueConst /*this_val*/,
                          int argc, JSValueConst* argv) {
    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "kv.scan requires at least 1 argument (prefix)");
    }
    
    const char* prefix = JS_ToCString(ctx, argv[0]);
    if (!prefix) {
        return JS_ThrowTypeError(ctx, "kv.scan: prefix must be a string");
    }
    
    size_t limit = 100;
    if (argc >= 2 && !JS_IsUndefined(argv[1]) && !JS_IsNull(argv[1])) {
        int64_t limit_val;
        if (JS_ToInt64(ctx, &limit_val, argv[1]) == 0 && limit_val > 0) {
            limit = static_cast<size_t>(limit_val);
        }
    }
    
    auto keys = KvStore::instance().scan(prefix, limit);
    JS_FreeCString(ctx, prefix);
    
    JSValue arr = JS_NewArray(ctx);
    for (size_t i = 0; i < keys.size(); i++) {
        JS_SetPropertyUint32(ctx, arr, static_cast<uint32_t>(i), 
                            JS_NewString(ctx, keys[i].c_str()));
    }
    
    return arr;
}

// kv.entries(prefix, limit?) -> [key, value][]
static JSValue js_kv_entries(JSContext* ctx, JSValueConst /*this_val*/,
                             int argc, JSValueConst* argv) {
    if (argc < 1) {
        return JS_ThrowTypeError(ctx, "kv.entries requires at least 1 argument (prefix)");
    }
    
    const char* prefix = JS_ToCString(ctx, argv[0]);
    if (!prefix) {
        return JS_ThrowTypeError(ctx, "kv.entries: prefix must be a string");
    }
    
    size_t limit = 100;
    if (argc >= 2 && !JS_IsUndefined(argv[1]) && !JS_IsNull(argv[1])) {
        int64_t limit_val;
        if (JS_ToInt64(ctx, &limit_val, argv[1]) == 0 && limit_val > 0) {
            limit = static_cast<size_t>(limit_val);
        }
    }
    
    auto pairs = KvStore::instance().scan_pairs(prefix, limit);
    JS_FreeCString(ctx, prefix);
    
    JSValue arr = JS_NewArray(ctx);
    for (size_t i = 0; i < pairs.size(); i++) {
        JSValue pair = JS_NewArray(ctx);
        JS_SetPropertyUint32(ctx, pair, 0, JS_NewString(ctx, pairs[i].first.c_str()));
        JS_SetPropertyUint32(ctx, pair, 1, JS_NewString(ctx, pairs[i].second.c_str()));
        JS_SetPropertyUint32(ctx, arr, static_cast<uint32_t>(i), pair);
    }
    
    return arr;
}

// kv.size() -> number
static JSValue js_kv_size(JSContext* ctx, JSValueConst /*this_val*/,
                          int /*argc*/, JSValueConst* /*argv*/) {
    return JS_NewInt64(ctx, static_cast<int64_t>(KvStore::instance().size()));
}

// Module initialization function that returns the module namespace object
static JSValue js_kv_module_init(JSContext* ctx, JSValueConst /*this_val*/,
                                  int /*argc*/, JSValueConst* /*argv*/) {
    JSValue exports = JS_NewObject(ctx);
    
    // Create kv object
    JSValue kv = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, kv, "get", JS_NewCFunction(ctx, js_kv_get, "get", 1));
    JS_SetPropertyStr(ctx, kv, "set", JS_NewCFunction(ctx, js_kv_set, "set", 3));
    JS_SetPropertyStr(ctx, kv, "del", JS_NewCFunction(ctx, js_kv_del, "del", 1));
    JS_SetPropertyStr(ctx, kv, "delete", JS_NewCFunction(ctx, js_kv_del, "delete", 1));
    JS_SetPropertyStr(ctx, kv, "exists", JS_NewCFunction(ctx, js_kv_exists, "exists", 1));
    JS_SetPropertyStr(ctx, kv, "ttl", JS_NewCFunction(ctx, js_kv_ttl, "ttl", 1));
    JS_SetPropertyStr(ctx, kv, "scan", JS_NewCFunction(ctx, js_kv_scan, "scan", 2));
    JS_SetPropertyStr(ctx, kv, "entries", JS_NewCFunction(ctx, js_kv_entries, "entries", 2));
    JS_SetPropertyStr(ctx, kv, "size", JS_NewCFunction(ctx, js_kv_size, "size", 0));
    
    JS_SetPropertyStr(ctx, exports, "kv", kv);
    
    return exports;
}

void setup_kv_module(JSContext* ctx) {
    JSValue global = JS_GetGlobalObject(ctx);
    
    // Register the module initializer - module resolver will use this
    JS_SetPropertyStr(ctx, global, "__quickw_kv_module__",
        JS_NewCFunction(ctx, js_kv_module_init, "__quickw_kv_module__", 0));
    
    JS_FreeValue(ctx, global);
}

// ============================================================================
// Web Streams and Blob Polyfills (Pure JavaScript implementation)
// ============================================================================

static const char* streams_polyfill_source = R"JS(
// ============================================================================
// Blob Implementation
// ============================================================================
(function(globalThis) {
    'use strict';

    class Blob {
        #parts = [];
        #type = '';
        #size = 0;

        constructor(blobParts = [], options = {}) {
            this.#type = options.type ? String(options.type).toLowerCase() : '';
            
            for (const part of blobParts) {
                if (part instanceof Blob) {
                    // Copy data from another Blob
                    this.#parts.push(...part.#parts);
                    this.#size += part.size;
                } else if (part instanceof ArrayBuffer) {
                    const copy = new Uint8Array(part).slice();
                    this.#parts.push(copy);
                    this.#size += copy.length;
                } else if (ArrayBuffer.isView(part)) {
                    const copy = new Uint8Array(part.buffer, part.byteOffset, part.byteLength).slice();
                    this.#parts.push(copy);
                    this.#size += copy.length;
                } else {
                    // Convert to string
                    const str = String(part);
                    const encoder = new TextEncoder();
                    const encoded = encoder.encode(str);
                    this.#parts.push(encoded);
                    this.#size += encoded.length;
                }
            }
        }

        get size() {
            return this.#size;
        }

        get type() {
            return this.#type;
        }

        async text() {
            const buffer = await this.arrayBuffer();
            const decoder = new TextDecoder();
            return decoder.decode(buffer);
        }

        async arrayBuffer() {
            const result = new Uint8Array(this.#size);
            let offset = 0;
            for (const part of this.#parts) {
                result.set(part, offset);
                offset += part.length;
            }
            return result.buffer;
        }

        async bytes() {
            const buffer = await this.arrayBuffer();
            return new Uint8Array(buffer);
        }

        slice(start = 0, end = this.#size, contentType = '') {
            // Normalize start and end
            if (start < 0) start = Math.max(this.#size + start, 0);
            if (end < 0) end = Math.max(this.#size + end, 0);
            start = Math.min(start, this.#size);
            end = Math.min(end, this.#size);
            
            if (start >= end) {
                return new Blob([], { type: contentType });
            }

            // Collect the bytes in the range
            const resultParts = [];
            let currentOffset = 0;
            
            for (const part of this.#parts) {
                const partStart = currentOffset;
                const partEnd = currentOffset + part.length;
                
                if (partEnd <= start) {
                    currentOffset = partEnd;
                    continue;
                }
                
                if (partStart >= end) {
                    break;
                }
                
                // Calculate slice within this part
                const sliceStart = Math.max(0, start - partStart);
                const sliceEnd = Math.min(part.length, end - partStart);
                
                resultParts.push(part.slice(sliceStart, sliceEnd));
                currentOffset = partEnd;
            }

            return new Blob(resultParts, { type: contentType });
        }

        stream() {
            const parts = this.#parts;
            let partIndex = 0;
            
            return new ReadableStream({
                pull(controller) {
                    if (partIndex >= parts.length) {
                        controller.close();
                        return;
                    }
                    controller.enqueue(parts[partIndex++]);
                }
            });
        }
    }

    // ============================================================================
    // ReadableStream Implementation
    // ============================================================================
    
    const ReadableStreamState = {
        READABLE: 'readable',
        CLOSED: 'closed',
        ERRORED: 'errored'
    };

    class ReadableStreamDefaultReader {
        #stream = null;
        #closedPromise = null;
        #closedResolve = null;
        #closedReject = null;

        constructor(stream) {
            if (stream._reader) {
                throw new TypeError('ReadableStream is already locked');
            }
            this.#stream = stream;
            stream._reader = this;
            
            this.#closedPromise = new Promise((resolve, reject) => {
                this.#closedResolve = resolve;
                this.#closedReject = reject;
            });

            if (stream._state === ReadableStreamState.CLOSED) {
                this.#closedResolve(undefined);
            } else if (stream._state === ReadableStreamState.ERRORED) {
                this.#closedReject(stream._storedError);
            }
        }

        get closed() {
            return this.#closedPromise;
        }

        async read() {
            if (!this.#stream) {
                return Promise.reject(new TypeError('Reader has been released'));
            }

            const stream = this.#stream;

            if (stream._state === ReadableStreamState.CLOSED) {
                return { done: true, value: undefined };
            }

            if (stream._state === ReadableStreamState.ERRORED) {
                throw stream._storedError;
            }

            // Check queue first
            if (stream._queue.length > 0) {
                const chunk = stream._queue.shift();
                stream._queueTotalSize -= chunk.byteLength || chunk.length || 1;
                
                if (stream._closeRequested && stream._queue.length === 0) {
                    stream._state = ReadableStreamState.CLOSED;
                    this.#closedResolve(undefined);
                } else if (stream._underlyingSource && stream._underlyingSource.pull) {
                    // Pull more data
                    try {
                        await stream._underlyingSource.pull(stream._controller);
                    } catch (e) {
                        stream._state = ReadableStreamState.ERRORED;
                        stream._storedError = e;
                        this.#closedReject(e);
                        throw e;
                    }
                }
                
                return { done: false, value: chunk };
            }

            // Queue is empty, need to pull
            if (stream._underlyingSource && stream._underlyingSource.pull) {
                return new Promise(async (resolve, reject) => {
                    stream._pendingReads.push({ resolve, reject });
                    
                    try {
                        await stream._underlyingSource.pull(stream._controller);
                    } catch (e) {
                        stream._state = ReadableStreamState.ERRORED;
                        stream._storedError = e;
                        this.#closedReject(e);
                        reject(e);
                    }
                });
            }

            // No pull function and queue is empty
            if (stream._closeRequested) {
                stream._state = ReadableStreamState.CLOSED;
                this.#closedResolve(undefined);
                return { done: true, value: undefined };
            }

            // Wait for data to be enqueued
            return new Promise((resolve, reject) => {
                stream._pendingReads.push({ resolve, reject });
            });
        }

        releaseLock() {
            if (!this.#stream) return;
            this.#stream._reader = null;
            this.#stream = null;
        }

        cancel(reason) {
            if (!this.#stream) {
                return Promise.reject(new TypeError('Reader has been released'));
            }
            return this.#stream.cancel(reason);
        }

        _close() {
            this.#closedResolve(undefined);
        }

        _error(e) {
            this.#closedReject(e);
        }
    }

    class ReadableStreamDefaultController {
        #stream = null;

        constructor(stream) {
            this.#stream = stream;
        }

        get desiredSize() {
            const stream = this.#stream;
            if (stream._state === ReadableStreamState.ERRORED) return null;
            if (stream._state === ReadableStreamState.CLOSED) return 0;
            return stream._highWaterMark - stream._queueTotalSize;
        }

        enqueue(chunk) {
            const stream = this.#stream;
            
            if (stream._state !== ReadableStreamState.READABLE) {
                throw new TypeError('Stream is not readable');
            }
            
            if (stream._closeRequested) {
                throw new TypeError('Stream is closing');
            }

            // If there are pending reads, fulfill them directly
            if (stream._pendingReads.length > 0) {
                const { resolve } = stream._pendingReads.shift();
                resolve({ done: false, value: chunk });
                return;
            }

            // Otherwise queue the chunk
            stream._queue.push(chunk);
            stream._queueTotalSize += chunk.byteLength || chunk.length || 1;
        }

        close() {
            const stream = this.#stream;
            
            if (stream._state !== ReadableStreamState.READABLE) {
                throw new TypeError('Stream is not readable');
            }
            
            if (stream._closeRequested) {
                throw new TypeError('Stream is already closing');
            }

            stream._closeRequested = true;

            if (stream._queue.length === 0) {
                stream._state = ReadableStreamState.CLOSED;
                
                // Resolve all pending reads with done
                while (stream._pendingReads.length > 0) {
                    const { resolve } = stream._pendingReads.shift();
                    resolve({ done: true, value: undefined });
                }
                
                if (stream._reader) {
                    stream._reader._close();
                }
            }
        }

        error(e) {
            const stream = this.#stream;
            
            if (stream._state !== ReadableStreamState.READABLE) {
                return;
            }

            stream._state = ReadableStreamState.ERRORED;
            stream._storedError = e;
            stream._queue = [];
            stream._queueTotalSize = 0;

            // Reject all pending reads
            while (stream._pendingReads.length > 0) {
                const { reject } = stream._pendingReads.shift();
                reject(e);
            }

            if (stream._reader) {
                stream._reader._error(e);
            }
        }
    }

    class ReadableStream {
        _state = ReadableStreamState.READABLE;
        _reader = null;
        _storedError = undefined;
        _underlyingSource = null;
        _controller = null;
        _queue = [];
        _queueTotalSize = 0;
        _highWaterMark = 1;
        _closeRequested = false;
        _pendingReads = [];

        constructor(underlyingSource = {}, strategy = {}) {
            this._underlyingSource = underlyingSource;
            this._highWaterMark = strategy.highWaterMark ?? 1;
            this._controller = new ReadableStreamDefaultController(this);

            if (underlyingSource.start) {
                const result = underlyingSource.start(this._controller);
                if (result && typeof result.then === 'function') {
                    result.catch(e => this._controller.error(e));
                }
            }
        }

        get locked() {
            return this._reader !== null;
        }

        async cancel(reason) {
            if (this._reader) {
                throw new TypeError('Cannot cancel a locked stream');
            }

            if (this._state === ReadableStreamState.CLOSED) {
                return;
            }

            if (this._state === ReadableStreamState.ERRORED) {
                throw this._storedError;
            }

            this._state = ReadableStreamState.CLOSED;
            this._queue = [];
            this._queueTotalSize = 0;

            if (this._underlyingSource && this._underlyingSource.cancel) {
                await this._underlyingSource.cancel(reason);
            }
        }

        getReader(options = {}) {
            if (options.mode === 'byob') {
                throw new TypeError('BYOB readers are not supported');
            }
            return new ReadableStreamDefaultReader(this);
        }

        tee() {
            if (this.locked) {
                throw new TypeError('Cannot tee a locked stream');
            }

            const reader = this.getReader();
            let reading = false;
            let readAgain = false;
            let canceled1 = false;
            let canceled2 = false;
            let reason1, reason2;
            let branch1Controller, branch2Controller;
            let branch1Closed = false;
            let branch2Closed = false;

            const pullAlgorithm = async () => {
                if (reading) {
                    readAgain = true;
                    return;
                }
                reading = true;
                
                try {
                    const { done, value } = await reader.read();
                    reading = false;
                    
                    if (done) {
                        if (!canceled1 && !branch1Closed) {
                            branch1Closed = true;
                            branch1Controller.close();
                        }
                        if (!canceled2 && !branch2Closed) {
                            branch2Closed = true;
                            branch2Controller.close();
                        }
                        return;
                    }
                    
                    // Clone the chunk for both branches
                    const chunk1 = value;
                    let chunk2;
                    if (value instanceof Uint8Array) {
                        chunk2 = new Uint8Array(value);
                    } else if (ArrayBuffer.isView(value)) {
                        chunk2 = new Uint8Array(value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength));
                    } else {
                        chunk2 = value;
                    }
                    
                    if (!canceled1 && !branch1Closed) branch1Controller.enqueue(chunk1);
                    if (!canceled2 && !branch2Closed) branch2Controller.enqueue(chunk2);
                    
                    if (readAgain) {
                        readAgain = false;
                        await pullAlgorithm();
                    }
                } catch (e) {
                    reading = false;
                    if (!branch1Closed) branch1Controller.error(e);
                    if (!branch2Closed) branch2Controller.error(e);
                }
            };

            const branch1 = new ReadableStream({
                start(controller) {
                    branch1Controller = controller;
                },
                pull: pullAlgorithm,
                cancel(reason) {
                    canceled1 = true;
                    reason1 = reason;
                    if (canceled2) {
                        reader.cancel([reason1, reason2]);
                    }
                }
            });

            const branch2 = new ReadableStream({
                start(controller) {
                    branch2Controller = controller;
                },
                pull: pullAlgorithm,
                cancel(reason) {
                    canceled2 = true;
                    reason2 = reason;
                    if (canceled1) {
                        reader.cancel([reason1, reason2]);
                    }
                }
            });

            return [branch1, branch2];
        }

        pipeThrough(transform, options = {}) {
            if (this.locked) {
                throw new TypeError('Cannot pipe a locked stream');
            }
            
            this.pipeTo(transform.writable, options);
            return transform.readable;
        }

        async pipeTo(destination, options = {}) {
            if (this.locked) {
                throw new TypeError('Cannot pipe a locked stream');
            }
            if (destination.locked) {
                throw new TypeError('Cannot pipe to a locked stream');
            }

            const reader = this.getReader();
            const writer = destination.getWriter();
            const preventClose = options.preventClose === true;
            const preventAbort = options.preventAbort === true;
            const preventCancel = options.preventCancel === true;
            const signal = options.signal;

            let shuttingDown = false;

            if (signal) {
                if (signal.aborted) {
                    throw signal.reason || new DOMException('Aborted', 'AbortError');
                }
                signal.addEventListener('abort', () => {
                    shuttingDown = true;
                });
            }

            try {
                while (true) {
                    if (shuttingDown) break;
                    
                    const { done, value } = await reader.read();
                    if (done) break;
                    
                    await writer.write(value);
                }
                
                if (!preventClose) {
                    await writer.close();
                }
            } catch (e) {
                if (!preventAbort) {
                    await writer.abort(e);
                }
                if (!preventCancel) {
                    await reader.cancel(e);
                }
                throw e;
            } finally {
                reader.releaseLock();
                writer.releaseLock();
            }
        }

        async *[Symbol.asyncIterator]() {
            const reader = this.getReader();
            try {
                while (true) {
                    const { done, value } = await reader.read();
                    if (done) break;
                    yield value;
                }
            } finally {
                reader.releaseLock();
            }
        }

        // Static methods
        static from(asyncIterable) {
            return new ReadableStream({
                async start(controller) {
                    for await (const chunk of asyncIterable) {
                        controller.enqueue(chunk);
                    }
                    controller.close();
                }
            });
        }
    }

    // ============================================================================
    // WritableStream Implementation
    // ============================================================================

    const WritableStreamState = {
        WRITABLE: 'writable',
        CLOSED: 'closed',
        ERRORING: 'erroring',
        ERRORED: 'errored'
    };

    class WritableStreamDefaultWriter {
        #stream = null;
        #closedPromise = null;
        #closedResolve = null;
        #closedReject = null;
        #readyPromise = null;
        #readyResolve = null;
        #readyReject = null;

        constructor(stream) {
            if (stream._writer) {
                throw new TypeError('WritableStream is already locked');
            }
            this.#stream = stream;
            stream._writer = this;

            this.#closedPromise = new Promise((resolve, reject) => {
                this.#closedResolve = resolve;
                this.#closedReject = reject;
            });

            this.#readyPromise = new Promise((resolve, reject) => {
                this.#readyResolve = resolve;
                this.#readyReject = reject;
            });

            if (stream._state === WritableStreamState.CLOSED) {
                this.#closedResolve(undefined);
                this.#readyResolve(undefined);
            } else if (stream._state === WritableStreamState.ERRORED) {
                this.#closedReject(stream._storedError);
                this.#readyReject(stream._storedError);
            } else {
                this.#readyResolve(undefined);
            }
        }

        get closed() {
            return this.#closedPromise;
        }

        get ready() {
            return this.#readyPromise;
        }

        get desiredSize() {
            const stream = this.#stream;
            if (!stream) return null;
            if (stream._state === WritableStreamState.ERRORED) return null;
            if (stream._state === WritableStreamState.CLOSED) return 0;
            return stream._highWaterMark - stream._queueTotalSize;
        }

        async write(chunk) {
            if (!this.#stream) {
                throw new TypeError('Writer has been released');
            }

            const stream = this.#stream;

            if (stream._state !== WritableStreamState.WRITABLE) {
                if (stream._state === WritableStreamState.ERRORED) {
                    throw stream._storedError;
                }
                throw new TypeError('Stream is not writable');
            }

            // Add to queue
            stream._queue.push({ chunk });
            stream._queueTotalSize += chunk.byteLength || chunk.length || 1;

            // Process queue
            return stream._processQueue();
        }

        async close() {
            if (!this.#stream) {
                throw new TypeError('Writer has been released');
            }

            const stream = this.#stream;

            if (stream._state !== WritableStreamState.WRITABLE) {
                throw new TypeError('Stream is not writable');
            }

            stream._closeRequested = true;

            // Wait for queue to drain
            await stream._processQueue();

            // Call underlying close
            if (stream._underlyingSink && stream._underlyingSink.close) {
                await stream._underlyingSink.close(stream._controller);
            }

            stream._state = WritableStreamState.CLOSED;
            this.#closedResolve(undefined);
        }

        async abort(reason) {
            if (!this.#stream) {
                throw new TypeError('Writer has been released');
            }

            return this.#stream.abort(reason);
        }

        releaseLock() {
            if (!this.#stream) return;
            this.#stream._writer = null;
            this.#stream = null;
        }

        _close() {
            this.#closedResolve(undefined);
        }

        _error(e) {
            this.#closedReject(e);
            this.#readyReject(e);
        }
    }

    class WritableStreamDefaultController {
        #stream = null;
        #signal = null;

        constructor(stream) {
            this.#stream = stream;
            // AbortController is used to signal abort to the underlying sink
            if (typeof AbortController !== 'undefined') {
                const controller = new AbortController();
                this.#signal = controller.signal;
            }
        }

        get signal() {
            return this.#signal;
        }

        error(e) {
            const stream = this.#stream;
            
            if (stream._state !== WritableStreamState.WRITABLE) {
                return;
            }

            stream._state = WritableStreamState.ERRORED;
            stream._storedError = e;
            stream._queue = [];
            stream._queueTotalSize = 0;

            if (stream._writer) {
                stream._writer._error(e);
            }
        }
    }

    class WritableStream {
        _state = WritableStreamState.WRITABLE;
        _writer = null;
        _storedError = undefined;
        _underlyingSink = null;
        _controller = null;
        _queue = [];
        _queueTotalSize = 0;
        _highWaterMark = 1;
        _closeRequested = false;
        _inFlightWriteRequest = null;
        _pendingAbortRequest = null;

        constructor(underlyingSink = {}, strategy = {}) {
            this._underlyingSink = underlyingSink;
            this._highWaterMark = strategy.highWaterMark ?? 1;
            this._controller = new WritableStreamDefaultController(this);

            if (underlyingSink.start) {
                const result = underlyingSink.start(this._controller);
                if (result && typeof result.then === 'function') {
                    result.catch(e => this._controller.error(e));
                }
            }
        }

        get locked() {
            return this._writer !== null;
        }

        async abort(reason) {
            if (this._writer) {
                throw new TypeError('Cannot abort a locked stream');
            }

            if (this._state === WritableStreamState.CLOSED) {
                return;
            }

            if (this._state === WritableStreamState.ERRORED) {
                throw this._storedError;
            }

            this._state = WritableStreamState.ERRORED;
            this._storedError = reason;
            this._queue = [];
            this._queueTotalSize = 0;

            if (this._underlyingSink && this._underlyingSink.abort) {
                await this._underlyingSink.abort(reason);
            }
        }

        async close() {
            if (this._writer) {
                throw new TypeError('Cannot close a locked stream');
            }

            if (this._state !== WritableStreamState.WRITABLE) {
                throw new TypeError('Stream is not writable');
            }

            this._closeRequested = true;

            // Wait for queue to drain
            await this._processQueue();

            if (this._underlyingSink && this._underlyingSink.close) {
                await this._underlyingSink.close(this._controller);
            }

            this._state = WritableStreamState.CLOSED;
        }

        getWriter() {
            return new WritableStreamDefaultWriter(this);
        }

        async _processQueue() {
            if (this._state !== WritableStreamState.WRITABLE) {
                return;
            }

            while (this._queue.length > 0) {
                const { chunk } = this._queue.shift();
                this._queueTotalSize -= chunk.byteLength || chunk.length || 1;

                if (this._underlyingSink && this._underlyingSink.write) {
                    try {
                        await this._underlyingSink.write(chunk, this._controller);
                    } catch (e) {
                        this._controller.error(e);
                        throw e;
                    }
                }
            }
        }
    }

    // ============================================================================
    // TransformStream Implementation (bonus - useful for pipeThrough)
    // ============================================================================

    class TransformStream {
        readable;
        writable;

        constructor(transformer = {}, writableStrategy = {}, readableStrategy = {}) {
            let readableController;
            
            this.readable = new ReadableStream({
                start(controller) {
                    readableController = controller;
                }
            }, readableStrategy);

            const transformController = {
                enqueue: (chunk) => readableController.enqueue(chunk),
                error: (e) => readableController.error(e),
                terminate: () => readableController.close()
            };

            this.writable = new WritableStream({
                start: transformer.start ? () => transformer.start(transformController) : undefined,
                write: transformer.transform 
                    ? async (chunk) => {
                        await transformer.transform(chunk, transformController);
                    }
                    : (chunk) => readableController.enqueue(chunk),
                close: transformer.flush
                    ? async () => {
                        await transformer.flush(transformController);
                        readableController.close();
                    }
                    : () => readableController.close(),
                abort: (reason) => readableController.error(reason)
            }, writableStrategy);
        }
    }

    // ============================================================================
    // TextEncoder Implementation (if not already present)
    // ============================================================================
    if (typeof globalThis.TextEncoder === 'undefined') {
        class TextEncoder {
            get encoding() {
                return 'utf-8';
            }

            encode(input = '') {
                const str = String(input);
                const len = str.length;
                let resPos = -1;
                const resArr = new Uint8Array(len * 3);
                
                for (let point = 0, nextcode = 0, i = 0; i !== len;) {
                    point = str.charCodeAt(i);
                    i += 1;
                    
                    if (point >= 0xD800 && point <= 0xDBFF) {
                        if (i === len) {
                            resArr[resPos += 1] = 0xef;
                            resArr[resPos += 1] = 0xbf;
                            resArr[resPos += 1] = 0xbd;
                            break;
                        }
                        nextcode = str.charCodeAt(i);
                        if (nextcode >= 0xDC00 && nextcode <= 0xDFFF) {
                            point = (point - 0xD800) * 0x400 + nextcode - 0xDC00 + 0x10000;
                            i += 1;
                            if (point > 0xffff) {
                                resArr[resPos += 1] = (0x1e << 3) | (point >>> 18);
                                resArr[resPos += 1] = (0x2 << 6) | ((point >>> 12) & 0x3f);
                                resArr[resPos += 1] = (0x2 << 6) | ((point >>> 6) & 0x3f);
                                resArr[resPos += 1] = (0x2 << 6) | (point & 0x3f);
                                continue;
                            }
                        } else {
                            resArr[resPos += 1] = 0xef;
                            resArr[resPos += 1] = 0xbf;
                            resArr[resPos += 1] = 0xbd;
                            continue;
                        }
                    }
                    
                    if (point <= 0x007f) {
                        resArr[resPos += 1] = (0x0 << 7) | point;
                    } else if (point <= 0x07ff) {
                        resArr[resPos += 1] = (0x6 << 5) | (point >>> 6);
                        resArr[resPos += 1] = (0x2 << 6) | (point & 0x3f);
                    } else {
                        resArr[resPos += 1] = (0xe << 4) | (point >>> 12);
                        resArr[resPos += 1] = (0x2 << 6) | ((point >>> 6) & 0x3f);
                        resArr[resPos += 1] = (0x2 << 6) | (point & 0x3f);
                    }
                }
                
                return resArr.subarray(0, resPos + 1);
            }

            encodeInto(source, destination) {
                const encoded = this.encode(source);
                const len = Math.min(encoded.length, destination.length);
                destination.set(encoded.subarray(0, len));
                return { read: source.length, written: len };
            }
        }
        globalThis.TextEncoder = TextEncoder;
    }

    // ============================================================================
    // ByteLengthQueuingStrategy and CountQueuingStrategy
    // ============================================================================
    class ByteLengthQueuingStrategy {
        #highWaterMark;

        constructor({ highWaterMark }) {
            this.#highWaterMark = highWaterMark;
        }

        get highWaterMark() {
            return this.#highWaterMark;
        }

        get size() {
            return (chunk) => chunk.byteLength;
        }
    }

    class CountQueuingStrategy {
        #highWaterMark;

        constructor({ highWaterMark }) {
            this.#highWaterMark = highWaterMark;
        }

        get highWaterMark() {
            return this.#highWaterMark;
        }

        get size() {
            return () => 1;
        }
    }

    // ============================================================================
    // Node.js Polyfills (Buffer, process) for compatibility with npm packages
    // ============================================================================
    
    // Minimal Buffer implementation
    if (typeof globalThis.Buffer === 'undefined') {
        class Buffer extends Uint8Array {
            static isBuffer(obj) {
                return obj instanceof Buffer;
            }
            
            static from(value, encodingOrOffset, length) {
                if (typeof value === 'string') {
                    const encoding = encodingOrOffset || 'utf-8';
                    if (encoding === 'base64') {
                        const binary = atob(value);
                        const bytes = new Uint8Array(binary.length);
                        for (let i = 0; i < binary.length; i++) {
                            bytes[i] = binary.charCodeAt(i);
                        }
                        return new Buffer(bytes);
                    } else if (encoding === 'hex') {
                        const bytes = new Uint8Array(value.length / 2);
                        for (let i = 0; i < value.length; i += 2) {
                            bytes[i / 2] = parseInt(value.substr(i, 2), 16);
                        }
                        return new Buffer(bytes);
                    } else {
                        // utf-8
                        const encoder = new TextEncoder();
                        return new Buffer(encoder.encode(value));
                    }
                } else if (value instanceof ArrayBuffer) {
                    return new Buffer(new Uint8Array(value, encodingOrOffset, length));
                } else if (ArrayBuffer.isView(value)) {
                    return new Buffer(new Uint8Array(value.buffer, value.byteOffset, value.byteLength));
                } else if (Array.isArray(value)) {
                    return new Buffer(value);
                }
                return new Buffer(value);
            }
            
            static alloc(size, fill = 0, encoding) {
                const buf = new Buffer(size);
                if (fill !== 0) {
                    buf.fill(fill);
                }
                return buf;
            }
            
            static allocUnsafe(size) {
                return new Buffer(size);
            }
            
            static concat(list, totalLength) {
                if (totalLength === undefined) {
                    totalLength = list.reduce((acc, buf) => acc + buf.length, 0);
                }
                const result = new Buffer(totalLength);
                let offset = 0;
                for (const buf of list) {
                    result.set(buf, offset);
                    offset += buf.length;
                }
                return result;
            }
            
            static byteLength(string, encoding = 'utf-8') {
                if (typeof string !== 'string') {
                    return string.byteLength || string.length;
                }
                return Buffer.from(string, encoding).length;
            }
            
            toString(encoding = 'utf-8', start = 0, end = this.length) {
                const slice = this.subarray(start, end);
                if (encoding === 'base64') {
                    let binary = '';
                    for (let i = 0; i < slice.length; i++) {
                        binary += String.fromCharCode(slice[i]);
                    }
                    return btoa(binary);
                } else if (encoding === 'hex') {
                    return Array.from(slice)
                        .map(b => b.toString(16).padStart(2, '0'))
                        .join('');
                } else {
                    // utf-8
                    const decoder = new TextDecoder(encoding);
                    return decoder.decode(slice);
                }
            }
            
            write(string, offset = 0, length, encoding = 'utf-8') {
                const buf = Buffer.from(string, encoding);
                const bytesToWrite = Math.min(buf.length, length || buf.length, this.length - offset);
                this.set(buf.subarray(0, bytesToWrite), offset);
                return bytesToWrite;
            }
            
            copy(target, targetStart = 0, sourceStart = 0, sourceEnd = this.length) {
                const slice = this.subarray(sourceStart, sourceEnd);
                target.set(slice, targetStart);
                return slice.length;
            }
            
            slice(start, end) {
                return new Buffer(this.subarray(start, end));
            }
            
            readUInt8(offset) {
                return this[offset];
            }
            
            readUInt16BE(offset) {
                return (this[offset] << 8) | this[offset + 1];
            }
            
            readUInt16LE(offset) {
                return this[offset] | (this[offset + 1] << 8);
            }
            
            readUInt32BE(offset) {
                return (this[offset] * 0x1000000) + ((this[offset + 1] << 16) | (this[offset + 2] << 8) | this[offset + 3]);
            }
            
            readUInt32LE(offset) {
                return ((this[offset + 3] * 0x1000000) + ((this[offset + 2] << 16) | (this[offset + 1] << 8) | this[offset]));
            }
            
            readInt8(offset) {
                const val = this[offset];
                return val > 127 ? val - 256 : val;
            }
            
            readInt16BE(offset) {
                const val = this.readUInt16BE(offset);
                return val > 32767 ? val - 65536 : val;
            }
            
            readInt16LE(offset) {
                const val = this.readUInt16LE(offset);
                return val > 32767 ? val - 65536 : val;
            }
            
            readInt32BE(offset) {
                return (this[offset] << 24) | (this[offset + 1] << 16) | (this[offset + 2] << 8) | this[offset + 3];
            }
            
            readInt32LE(offset) {
                return (this[offset + 3] << 24) | (this[offset + 2] << 16) | (this[offset + 1] << 8) | this[offset];
            }
            
            writeUInt8(value, offset) {
                this[offset] = value & 0xff;
                return offset + 1;
            }
            
            writeUInt16BE(value, offset) {
                this[offset] = (value >>> 8) & 0xff;
                this[offset + 1] = value & 0xff;
                return offset + 2;
            }
            
            writeUInt16LE(value, offset) {
                this[offset] = value & 0xff;
                this[offset + 1] = (value >>> 8) & 0xff;
                return offset + 2;
            }
            
            writeUInt32BE(value, offset) {
                this[offset] = (value >>> 24) & 0xff;
                this[offset + 1] = (value >>> 16) & 0xff;
                this[offset + 2] = (value >>> 8) & 0xff;
                this[offset + 3] = value & 0xff;
                return offset + 4;
            }
            
            writeUInt32LE(value, offset) {
                this[offset] = value & 0xff;
                this[offset + 1] = (value >>> 8) & 0xff;
                this[offset + 2] = (value >>> 16) & 0xff;
                this[offset + 3] = (value >>> 24) & 0xff;
                return offset + 4;
            }
            
            writeInt8(value, offset) {
                if (value < 0) value = 256 + value;
                return this.writeUInt8(value, offset);
            }
            
            writeInt16BE(value, offset) {
                if (value < 0) value = 65536 + value;
                return this.writeUInt16BE(value, offset);
            }
            
            writeInt16LE(value, offset) {
                if (value < 0) value = 65536 + value;
                return this.writeUInt16LE(value, offset);
            }
            
            writeInt32BE(value, offset) {
                return this.writeUInt32BE(value >>> 0, offset);
            }
            
            writeInt32LE(value, offset) {
                return this.writeUInt32LE(value >>> 0, offset);
            }
            
            equals(other) {
                if (this.length !== other.length) return false;
                for (let i = 0; i < this.length; i++) {
                    if (this[i] !== other[i]) return false;
                }
                return true;
            }
            
            compare(other) {
                const len = Math.min(this.length, other.length);
                for (let i = 0; i < len; i++) {
                    if (this[i] < other[i]) return -1;
                    if (this[i] > other[i]) return 1;
                }
                if (this.length < other.length) return -1;
                if (this.length > other.length) return 1;
                return 0;
            }
            
            toJSON() {
                return { type: 'Buffer', data: Array.from(this) };
            }
        }
        
        globalThis.Buffer = Buffer;
    }
    
    // Minimal process polyfill
    if (typeof globalThis.process === 'undefined') {
        globalThis.process = {
            env: {},
            version: 'v18.0.0',
            versions: { node: '18.0.0' },
            platform: 'quickw',
            arch: 'unknown',
            pid: 1,
            cwd: () => '/',
            chdir: () => {},
            nextTick: (fn, ...args) => queueMicrotask ? queueMicrotask(() => fn(...args)) : setTimeout(() => fn(...args), 0),
            hrtime: {
                bigint: () => BigInt(Date.now()) * 1000000n
            },
            stdout: { write: (s) => console.log(s) },
            stderr: { write: (s) => console.error(s) },
            exit: () => {},
            on: () => {},
            off: () => {},
            emit: () => {},
            binding: () => ({}),
            umask: () => 0
        };
    }
    
    // queueMicrotask polyfill
    if (typeof globalThis.queueMicrotask === 'undefined') {
        globalThis.queueMicrotask = (fn) => Promise.resolve().then(fn);
    }

    // ============================================================================
    // Headers class (for fetch API compatibility)
    // ============================================================================
    class Headers {
        #headers = new Map();

        constructor(init) {
            if (init instanceof Headers) {
                init.forEach((value, name) => this.append(name, value));
            } else if (Array.isArray(init)) {
                for (const [name, value] of init) {
                    this.append(name, value);
                }
            } else if (init && typeof init === 'object') {
                for (const [name, value] of Object.entries(init)) {
                    this.append(name, value);
                }
            }
        }

        append(name, value) {
            name = String(name).toLowerCase();
            value = String(value);
            const existing = this.#headers.get(name);
            if (existing !== undefined) {
                this.#headers.set(name, existing + ', ' + value);
            } else {
                this.#headers.set(name, value);
            }
        }

        delete(name) {
            this.#headers.delete(String(name).toLowerCase());
        }

        get(name) {
            return this.#headers.get(String(name).toLowerCase()) || null;
        }

        has(name) {
            return this.#headers.has(String(name).toLowerCase());
        }

        set(name, value) {
            this.#headers.set(String(name).toLowerCase(), String(value));
        }

        forEach(callback, thisArg) {
            for (const [name, value] of this.#headers) {
                callback.call(thisArg, value, name, this);
            }
        }

        *entries() { yield* this.#headers.entries(); }
        *keys() { yield* this.#headers.keys(); }
        *values() { yield* this.#headers.values(); }
        [Symbol.iterator]() { return this.entries(); }
    }

    // ============================================================================
    // Request class (for fetch API compatibility)
    // ============================================================================
    class Request {
        #url;
        #method;
        #headers;
        #body;
        #bodyUsed = false;

        constructor(input, init = {}) {
            if (input instanceof Request) {
                this.#url = input.url;
                this.#method = init.method || input.method;
                this.#headers = new Headers(init.headers || input.headers);
                this.#body = init.body !== undefined ? init.body : input.#body;
            } else {
                this.#url = String(input);
                this.#method = init.method || 'GET';
                this.#headers = new Headers(init.headers);
                this.#body = init.body;
            }
        }

        get url() { return this.#url; }
        get method() { return this.#method.toUpperCase(); }
        get headers() { return this.#headers; }
        get body() { return this.#body; }
        get bodyUsed() { return this.#bodyUsed; }

        async text() {
            if (this.#bodyUsed) throw new TypeError('Body already used');
            this.#bodyUsed = true;
            if (this.#body === null || this.#body === undefined) return '';
            if (typeof this.#body === 'string') return this.#body;
            if (this.#body instanceof ArrayBuffer) return new TextDecoder().decode(this.#body);
            if (ArrayBuffer.isView(this.#body)) return new TextDecoder().decode(this.#body);
            return String(this.#body);
        }

        async json() {
            return JSON.parse(await this.text());
        }

        async arrayBuffer() {
            if (this.#bodyUsed) throw new TypeError('Body already used');
            this.#bodyUsed = true;
            if (this.#body === null || this.#body === undefined) return new ArrayBuffer(0);
            if (this.#body instanceof ArrayBuffer) return this.#body;
            if (ArrayBuffer.isView(this.#body)) return this.#body.buffer.slice(this.#body.byteOffset, this.#body.byteOffset + this.#body.byteLength);
            const encoder = new TextEncoder();
            return encoder.encode(String(this.#body)).buffer;
        }

        clone() {
            if (this.#bodyUsed) throw new TypeError('Body already used');
            return new Request(this.#url, {
                method: this.#method,
                headers: this.#headers,
                body: this.#body
            });
        }
    }

    // ============================================================================
    // Event / EventTarget polyfill
    // ============================================================================
    class Event {
        constructor(type, options = {}) {
            this.type = type;
            this.bubbles = !!options.bubbles;
            this.cancelable = !!options.cancelable;
            this.defaultPrevented = false;
            this.target = null;
            this.currentTarget = null;
            this.timeStamp = Date.now();
        }
        preventDefault() { 
            if (this.cancelable) this.defaultPrevented = true; 
        }
        stopPropagation() {}
        stopImmediatePropagation() {}
    }

    class EventTarget {
        #listeners = new Map();

        addEventListener(type, callback, options) {
            if (!this.#listeners.has(type)) {
                this.#listeners.set(type, []);
            }
            this.#listeners.get(type).push({ callback, options });
        }

        removeEventListener(type, callback) {
            if (!this.#listeners.has(type)) return;
            const arr = this.#listeners.get(type);
            const idx = arr.findIndex(l => l.callback === callback);
            if (idx !== -1) arr.splice(idx, 1);
        }

        dispatchEvent(event) {
            event.target = this;
            event.currentTarget = this;
            const listeners = this.#listeners.get(event.type) || [];
            for (const { callback } of listeners) {
                if (typeof callback === 'function') {
                    callback.call(this, event);
                } else if (callback && typeof callback.handleEvent === 'function') {
                    callback.handleEvent(event);
                }
            }
            return !event.defaultPrevented;
        }
    }

    // Simple DOMException if not available
    if (typeof globalThis.DOMException === 'undefined') {
        class DOMException extends Error {
            constructor(message, name) {
                super(message);
                this.name = name || 'DOMException';
            }
        }
        globalThis.DOMException = DOMException;
    }

    // ============================================================================
    // AbortController / AbortSignal polyfill
    // Used by fetch-based libraries for request cancellation/timeouts
    // ============================================================================
    class AbortSignal extends EventTarget {
        #aborted = false;
        #reason = undefined;

        get aborted() { return this.#aborted; }
        get reason() { return this.#reason; }

        static abort(reason) {
            const signal = new AbortSignal();
            signal.#aborted = true;
            signal.#reason = reason !== undefined ? reason : new DOMException('signal is aborted without reason', 'AbortError');
            return signal;
        }

        static timeout(ms) {
            const controller = new AbortController();
            setTimeout(() => {
                controller.abort(new DOMException('signal timed out', 'TimeoutError'));
            }, ms);
            return controller.signal;
        }

        throwIfAborted() {
            if (this.#aborted) {
                throw this.#reason;
            }
        }

        // Internal: called by AbortController
        _abort(reason) {
            if (this.#aborted) return;
            this.#aborted = true;
            this.#reason = reason !== undefined ? reason : new DOMException('signal is aborted without reason', 'AbortError');
            this.dispatchEvent(new Event('abort'));
        }
    }

    class AbortController {
        #signal = new AbortSignal();

        get signal() { return this.#signal; }

        abort(reason) {
            this.#signal._abort(reason);
        }
    }

    // ============================================================================
    // atob / btoa (Base64 encoding/decoding)
    // ============================================================================
    if (typeof globalThis.atob === 'undefined') {
        const b64chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
        const b64lookup = new Uint8Array(256);
        for (let i = 0; i < b64chars.length; i++) {
            b64lookup[b64chars.charCodeAt(i)] = i;
        }

        globalThis.btoa = function(data) {
            const str = String(data);
            let out = '';
            for (let i = 0; i < str.length; i += 3) {
                const c1 = str.charCodeAt(i);
                const c2 = str.charCodeAt(i + 1);
                const c3 = str.charCodeAt(i + 2);
                out += b64chars[c1 >> 2];
                out += b64chars[((c1 & 3) << 4) | (c2 >> 4)];
                out += i + 1 < str.length ? b64chars[((c2 & 15) << 2) | (c3 >> 6)] : '=';
                out += i + 2 < str.length ? b64chars[c3 & 63] : '=';
            }
            return out;
        };

        globalThis.atob = function(data) {
            const str = String(data).replace(/=+$/, '');
            if (str.length % 4 === 1) {
                throw new DOMException('Invalid base64 string', 'InvalidCharacterError');
            }
            let out = '';
            for (let i = 0; i < str.length; i += 4) {
                const c1 = b64lookup[str.charCodeAt(i)];
                const c2 = b64lookup[str.charCodeAt(i + 1)];
                const c3 = b64lookup[str.charCodeAt(i + 2)];
                const c4 = b64lookup[str.charCodeAt(i + 3)];
                out += String.fromCharCode((c1 << 2) | (c2 >> 4));
                if (i + 2 < str.length) out += String.fromCharCode(((c2 & 15) << 4) | (c3 >> 2));
                if (i + 3 < str.length) out += String.fromCharCode(((c3 & 3) << 6) | c4);
            }
            return out;
        };
    }

    // ============================================================================
    // URLSearchParams implementation
    // ============================================================================
    if (typeof globalThis.URLSearchParams === 'undefined') {
        class URLSearchParams {
            #params = [];

            constructor(init) {
                if (typeof init === 'string') {
                    const str = init.startsWith('?') ? init.slice(1) : init;
                    if (str) {
                        for (const pair of str.split('&')) {
                            const [key, ...rest] = pair.split('=');
                            const value = rest.join('=');
                            this.#params.push([
                                decodeURIComponent(key.replace(/\+/g, ' ')),
                                decodeURIComponent((value || '').replace(/\+/g, ' '))
                            ]);
                        }
                    }
                } else if (Array.isArray(init)) {
                    for (const [key, value] of init) {
                        this.#params.push([String(key), String(value)]);
                    }
                } else if (init && typeof init === 'object') {
                    if (init instanceof URLSearchParams) {
                        for (const [key, value] of init) {
                            this.#params.push([key, value]);
                        }
                    } else {
                        for (const [key, value] of Object.entries(init)) {
                            this.#params.push([String(key), String(value)]);
                        }
                    }
                }
            }

            append(name, value) {
                this.#params.push([String(name), String(value)]);
            }

            delete(name) {
                this.#params = this.#params.filter(([k]) => k !== String(name));
            }

            get(name) {
                const found = this.#params.find(([k]) => k === String(name));
                return found ? found[1] : null;
            }

            getAll(name) {
                return this.#params.filter(([k]) => k === String(name)).map(([, v]) => v);
            }

            has(name) {
                return this.#params.some(([k]) => k === String(name));
            }

            set(name, value) {
                const n = String(name);
                const v = String(value);
                let found = false;
                this.#params = this.#params.filter(([k]) => {
                    if (k === n && !found) {
                        found = true;
                        return true;
                    }
                    return k !== n;
                });
                if (found) {
                    const idx = this.#params.findIndex(([k]) => k === n);
                    if (idx !== -1) this.#params[idx][1] = v;
                } else {
                    this.#params.push([n, v]);
                }
            }

            sort() {
                this.#params.sort((a, b) => a[0].localeCompare(b[0]));
            }

            toString() {
                return this.#params
                    .map(([k, v]) => encodeURIComponent(k) + '=' + encodeURIComponent(v))
                    .join('&');
            }

            forEach(callback, thisArg) {
                for (const [key, value] of this.#params) {
                    callback.call(thisArg, value, key, this);
                }
            }

            *entries() { yield* this.#params; }
            *keys() { for (const [k] of this.#params) yield k; }
            *values() { for (const [, v] of this.#params) yield v; }
            [Symbol.iterator]() { return this.entries(); }

            get size() { return this.#params.length; }
        }
        globalThis.URLSearchParams = URLSearchParams;
    }

    // ============================================================================
    // URL implementation
    // ============================================================================
    if (typeof globalThis.URL === 'undefined') {
        class URL {
            #protocol = '';
            #username = '';
            #password = '';
            #hostname = '';
            #port = '';
            #pathname = '/';
            #search = '';
            #hash = '';

            constructor(url, base) {
                let urlStr = String(url);
                
                // Handle relative URLs with base
                if (base !== undefined) {
                    const baseUrl = new URL(String(base));
                    if (!urlStr.match(/^[a-zA-Z][a-zA-Z0-9+.-]*:/)) {
                        // Relative URL
                        if (urlStr.startsWith('//')) {
                            urlStr = baseUrl.protocol + urlStr;
                        } else if (urlStr.startsWith('/')) {
                            urlStr = baseUrl.origin + urlStr;
                        } else if (urlStr.startsWith('?')) {
                            urlStr = baseUrl.origin + baseUrl.pathname + urlStr;
                        } else if (urlStr.startsWith('#')) {
                            urlStr = baseUrl.origin + baseUrl.pathname + baseUrl.search + urlStr;
                        } else {
                            // Relative path
                            const basePath = baseUrl.pathname.split('/').slice(0, -1).join('/');
                            urlStr = baseUrl.origin + basePath + '/' + urlStr;
                        }
                    }
                }

                // Parse the URL
                const match = urlStr.match(/^([a-zA-Z][a-zA-Z0-9+.-]*):\/\/(?:([^:@]*)(?::([^@]*))?@)?([^:/?#]*)(?::(\d+))?(\/[^?#]*)?(\?[^#]*)?(#.*)?$/);
                
                if (!match) {
                    throw new TypeError('Invalid URL: ' + url);
                }

                this.#protocol = match[1].toLowerCase() + ':';
                this.#username = match[2] ? decodeURIComponent(match[2]) : '';
                this.#password = match[3] ? decodeURIComponent(match[3]) : '';
                this.#hostname = match[4].toLowerCase();
                this.#port = match[5] || '';
                this.#pathname = match[6] || '/';
                this.#search = match[7] || '';
                this.#hash = match[8] || '';

                // Normalize pathname
                this.#pathname = this.#pathname.split('/').reduce((acc, seg) => {
                    if (seg === '..') acc.pop();
                    else if (seg !== '.' && seg !== '') acc.push(seg);
                    return acc;
                }, ['']).join('/') || '/';
            }

            get protocol() { return this.#protocol; }
            set protocol(v) { this.#protocol = String(v).toLowerCase().replace(/:*$/, ':'); }

            get username() { return this.#username; }
            set username(v) { this.#username = String(v); }

            get password() { return this.#password; }
            set password(v) { this.#password = String(v); }

            get hostname() { return this.#hostname; }
            set hostname(v) { this.#hostname = String(v).toLowerCase(); }

            get port() { return this.#port; }
            set port(v) { this.#port = String(v); }

            get host() {
                return this.#port ? this.#hostname + ':' + this.#port : this.#hostname;
            }
            set host(v) {
                const match = String(v).match(/^([^:]+)(?::(\d+))?$/);
                if (match) {
                    this.#hostname = match[1].toLowerCase();
                    this.#port = match[2] || '';
                }
            }

            get pathname() { return this.#pathname; }
            set pathname(v) { this.#pathname = '/' + String(v).replace(/^\/+/, ''); }

            get search() { return this.#search; }
            set search(v) {
                const s = String(v);
                this.#search = s ? (s.startsWith('?') ? s : '?' + s) : '';
            }

            get searchParams() {
                const params = new URLSearchParams(this.#search);
                const url = this;
                // Create a proxy to sync changes back to URL
                return new Proxy(params, {
                    get(target, prop) {
                        const value = target[prop];
                        if (typeof value === 'function') {
                            return function(...args) {
                                const result = value.apply(target, args);
                                if (['append', 'delete', 'set', 'sort'].includes(prop)) {
                                    url.#search = target.toString() ? '?' + target.toString() : '';
                                }
                                return result;
                            };
                        }
                        return value;
                    }
                });
            }

            get hash() { return this.#hash; }
            set hash(v) {
                const h = String(v);
                this.#hash = h ? (h.startsWith('#') ? h : '#' + h) : '';
            }

            get origin() {
                return this.#protocol + '//' + this.host;
            }

            get href() {
                let url = this.#protocol + '//';
                if (this.#username) {
                    url += encodeURIComponent(this.#username);
                    if (this.#password) url += ':' + encodeURIComponent(this.#password);
                    url += '@';
                }
                url += this.host + this.#pathname + this.#search + this.#hash;
                return url;
            }
            set href(v) {
                const parsed = new URL(String(v));
                this.#protocol = parsed.protocol;
                this.#username = parsed.username;
                this.#password = parsed.password;
                this.#hostname = parsed.hostname;
                this.#port = parsed.port;
                this.#pathname = parsed.pathname;
                this.#search = parsed.search;
                this.#hash = parsed.hash;
            }

            toString() { return this.href; }
            toJSON() { return this.href; }

            static canParse(url, base) {
                try {
                    new URL(url, base);
                    return true;
                } catch {
                    return false;
                }
            }
        }
        globalThis.URL = URL;
    }

    // ============================================================================
    // WebSocket stub (prevents errors from libraries that import isomorphic-ws)
    // The @libsql/client HTTP transport doesn't actually use WebSocket, but the
    // bundled code includes WebSocket references that fail if undefined
    // ============================================================================
    class WebSocket {
        static CONNECTING = 0;
        static OPEN = 1;
        static CLOSING = 2;
        static CLOSED = 3;

        constructor(url, protocols) {
            throw new Error('WebSocket is not supported in this runtime. Use HTTP transport instead.');
        }
    }

    // Export to global
    globalThis.Event = Event;
    globalThis.EventTarget = EventTarget;
    globalThis.Blob = Blob;
    globalThis.Headers = Headers;
    globalThis.Request = Request;
    globalThis.WebSocket = WebSocket;
    globalThis.AbortController = AbortController;
    globalThis.AbortSignal = AbortSignal;
    globalThis.ReadableStream = ReadableStream;
    globalThis.ReadableStreamDefaultReader = ReadableStreamDefaultReader;
    globalThis.WritableStream = WritableStream;
    globalThis.WritableStreamDefaultWriter = WritableStreamDefaultWriter;
    globalThis.TransformStream = TransformStream;
    globalThis.ByteLengthQueuingStrategy = ByteLengthQueuingStrategy;
    globalThis.CountQueuingStrategy = CountQueuingStrategy;

})(globalThis);
)JS";

void setup_streams_polyfill(JSContext* ctx) {
    JSValue result = JS_Eval(ctx, streams_polyfill_source, strlen(streams_polyfill_source),
                             "<streams-polyfill>", JS_EVAL_TYPE_GLOBAL);
    
    if (JS_IsException(result)) {
        JSValue exc = JS_GetException(ctx);
        const char* str = JS_ToCString(ctx, exc);
        if (str) {
            std::cerr << "Failed to initialize streams polyfill: " << str << std::endl;
            JS_FreeCString(ctx, str);
        }
        JS_FreeValue(ctx, exc);
    }
    JS_FreeValue(ctx, result);
}

}  // namespace quickwork::bindings
