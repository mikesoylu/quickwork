#include "js_bindings.hpp"
#include "js_runtime.hpp"

extern "C" {
#include "quickjs.h"
}

#include <curl/curl.h>
#include <iostream>
#include <sstream>
#include <unordered_map>

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

// ============================================================================
// Fetch API implementation using libcurl
// ============================================================================

// FetchResponse class for JS
static JSClassID js_fetch_response_class_id;

struct FetchResponseData {
    long status_code = 0;
    std::string body;
    std::unordered_map<std::string, std::string> headers;
};

static void js_fetch_response_finalizer(JSRuntime* /*rt*/, JSValue val) {
    auto* data = static_cast<FetchResponseData*>(JS_GetOpaque(val, js_fetch_response_class_id));
    delete data;
}

static JSClassDef js_fetch_response_class = {
    "FetchResponse",
    .finalizer = js_fetch_response_finalizer,
};

static JSValue js_fetch_response_json(JSContext* ctx, JSValueConst this_val,
                                      int /*argc*/, JSValueConst* /*argv*/) {
    auto* data = static_cast<FetchResponseData*>(JS_GetOpaque(this_val, js_fetch_response_class_id));
    if (!data) return JS_UNDEFINED;
    return JS_ParseJSON(ctx, data->body.c_str(), data->body.size(), "<fetch-json>");
}

static JSValue js_fetch_response_text(JSContext* ctx, JSValueConst this_val,
                                      int /*argc*/, JSValueConst* /*argv*/) {
    auto* data = static_cast<FetchResponseData*>(JS_GetOpaque(this_val, js_fetch_response_class_id));
    if (!data) return JS_UNDEFINED;
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
    
    // Perform the fetch (synchronously, but return a Promise for API compatibility)
    FetchResponse fetch_response = perform_fetch(url, method, headers, body);
    
    // Create response object using our FetchResponse class
    JSValue response_obj = JS_NewObjectClass(ctx, static_cast<int>(js_fetch_response_class_id));
    auto* response_data = new FetchResponseData();
    response_data->status_code = fetch_response.status_code;
    response_data->body = std::move(fetch_response.body);
    response_data->headers = std::move(fetch_response.headers);
    JS_SetOpaque(response_obj, response_data);
    
    // Return a resolved Promise
    JSValue resolving_funcs[2];
    JSValue promise = JS_NewPromiseCapability(ctx, resolving_funcs);
    if (JS_IsException(promise)) {
        JS_FreeValue(ctx, response_obj);
        return promise;
    }
    
    // If fetch failed (status_code == 0), reject the promise
    if (fetch_response.status_code == 0) {
        JSValue error = JS_NewError(ctx);
        // Copy error message before freeing response_obj (which owns response_data)
        std::string error_msg = response_data->body;
        JS_FreeValue(ctx, response_obj);
        JS_SetPropertyStr(ctx, error, "message", JS_NewString(ctx, error_msg.c_str()));
        JS_Call(ctx, resolving_funcs[1], JS_UNDEFINED, 1, &error);
        JS_FreeValue(ctx, error);
    } else {
        JS_Call(ctx, resolving_funcs[0], JS_UNDEFINED, 1, &response_obj);
        // JS_Call doesn't steal the reference, so we need to free our copy
        JS_FreeValue(ctx, response_obj);
    }
    
    JS_FreeValue(ctx, resolving_funcs[0]);
    JS_FreeValue(ctx, resolving_funcs[1]);
    
    return promise;
}

void setup_fetch(JSContext* ctx) {
    // Register FetchResponse class
    JS_NewClassID(&js_fetch_response_class_id);
    JS_NewClass(JS_GetRuntime(ctx), js_fetch_response_class_id, &js_fetch_response_class);
    
    JSValue proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, proto, js_fetch_response_proto_funcs,
                               sizeof(js_fetch_response_proto_funcs) / sizeof(js_fetch_response_proto_funcs[0]));
    JS_SetClassProto(ctx, js_fetch_response_class_id, proto);
    
    // Register fetch function
    JSValue global = JS_GetGlobalObject(ctx);
    JS_SetPropertyStr(ctx, global, "fetch",
        JS_NewCFunction(ctx, js_fetch, "fetch", 2));
    JS_FreeValue(ctx, global);
}

}  // namespace quickwork::bindings
