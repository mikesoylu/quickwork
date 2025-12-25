#pragma once

#include <string>
#include <unordered_map>
#include <vector>

struct JSContext;
struct JSValue;

namespace quickwork {
struct HttpRequest;
}

namespace quickwork::bindings {

void setup_console(JSContext* ctx);
void setup_crypto(JSContext* ctx);
void setup_request_class(JSContext* ctx);
void setup_response_class(JSContext* ctx);
void setup_stream_response_class(JSContext* ctx);
void setup_fetch(JSContext* ctx);
void setup_timers(JSContext* ctx);
void cleanup_timers(JSContext* ctx);
JSValue create_request(JSContext* ctx, const HttpRequest& request);

// Timer management - called from the event loop
bool process_timers(JSContext* ctx);
bool has_pending_timers(JSContext* ctx);

// StreamResponse data access
struct StreamResponseData {
    int status = 200;
    std::unordered_map<std::string, std::string> headers;
    std::vector<std::string> chunks;
    bool closed = false;
};

StreamResponseData* get_stream_response_data(JSContext* ctx, JSValue obj);

}  // namespace quickwork::bindings
