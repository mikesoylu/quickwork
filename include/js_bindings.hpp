#pragma once

struct JSContext;
struct JSValue;

namespace quickwork {
struct HttpRequest;
}

namespace quickwork::bindings {

void setup_console(JSContext* ctx);
void setup_request_class(JSContext* ctx);
void setup_response_class(JSContext* ctx);
void setup_fetch(JSContext* ctx);
void setup_timers(JSContext* ctx);
void cleanup_timers(JSContext* ctx);
JSValue create_request(JSContext* ctx, const HttpRequest& request);

// Timer management - called from the event loop
bool process_timers(JSContext* ctx);
bool has_pending_timers(JSContext* ctx);

}  // namespace quickwork::bindings
