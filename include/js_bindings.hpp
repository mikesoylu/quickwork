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
JSValue create_request(JSContext* ctx, const HttpRequest& request);

}  // namespace quickwork::bindings
