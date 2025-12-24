#include "js_bindings.hpp"
#include "js_runtime.hpp"

extern "C" {
#include "quickjs.h"
}

#include <iostream>

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

// Request class
static JSClassID js_request_class_id;

static void js_request_finalizer(JSRuntime* /*rt*/, JSValue val) {
    auto* req = static_cast<HttpRequest*>(JS_GetOpaque(val, js_request_class_id));
    delete req;
}

static JSClassDef js_request_class = {
    "Request",
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
    "Response",
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

}  // namespace quickwork::bindings
