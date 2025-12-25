#include "js_bindings.hpp"
#include "js_runtime.hpp"

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
    
    JSValue headers = JS_NewObject(ctx);
    for (const auto& [key, value] : data->headers) {
        JS_SetPropertyStr(ctx, headers, key.c_str(), JS_NewString(ctx, value.c_str()));
    }
    return headers;
}

static const JSCFunctionListEntry js_fetch_response_proto_funcs[] = {
    JS_CGETSET_DEF("status", js_fetch_response_get_status, nullptr),
    JS_CGETSET_DEF("ok", js_fetch_response_get_ok, nullptr),
    JS_CGETSET_DEF("body", js_fetch_response_get_body, nullptr),
    JS_CGETSET_DEF("headers", js_fetch_response_get_headers, nullptr),
    JS_CFUNC_DEF("json", 0, js_fetch_response_json),
    JS_CFUNC_DEF("text", 0, js_fetch_response_text),
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
    
    // Get URL
    const char* url_str = JS_ToCString(ctx, argv[0]);
    if (!url_str) {
        return JS_ThrowTypeError(ctx, "fetch: invalid URL");
    }
    std::string url(url_str);
    JS_FreeCString(ctx, url_str);
    
    // Parse options
    std::string method = "GET";
    std::string body;
    std::unordered_map<std::string, std::string> headers;
    
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

}  // namespace quickwork::bindings
