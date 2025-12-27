#pragma once

#include <functional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

struct JSContext;
struct JSValue;

namespace quickwork {
struct HttpRequest;
using StreamWriter = std::function<void(std::string_view chunk)>;
}

namespace quickwork::bindings {

void setup_console(JSContext* ctx);
void setup_crypto(JSContext* ctx);
void setup_request_class(JSContext* ctx);
void setup_response_class(JSContext* ctx);
void setup_stream_response_class(JSContext* ctx);
void setup_fetch(JSContext* ctx);
void setup_text_decoder(JSContext* ctx);
void setup_timers(JSContext* ctx);
void cleanup_timers(JSContext* ctx);
void setup_kv_module(JSContext* ctx);
JSValue create_request(JSContext* ctx, const HttpRequest& request);

// Returns the streams polyfill source code to be prepended during bytecode compilation
const char* get_streams_polyfill_source();

// Timer management - called from the event loop
bool process_timers(JSContext* ctx);
bool has_pending_timers(JSContext* ctx);

// Fetch management - called from the event loop
bool process_pending_fetches(JSContext* ctx);
bool has_pending_fetches(JSContext* ctx);
void cleanup_pending_fetches(JSContext* ctx);

// StreamResponse data access
struct StreamResponseData {
    int status = 200;
    std::unordered_map<std::string, std::string> headers;
    quickwork::StreamWriter writer;  // Callback to write chunks immediately
    bool headers_sent = false;
    bool closed = false;
};

StreamResponseData* get_stream_response_data(JSContext* ctx, JSValue obj);

// Set the stream writer for a context (called before executing handler)
void set_stream_writer(JSContext* ctx, quickwork::StreamWriter writer);

}  // namespace quickwork::bindings
