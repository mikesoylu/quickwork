#include "js_runtime.hpp"
#include "js_bindings.hpp"

#include <chrono>
#include <cstring>
#include <sstream>
#include <stdexcept>

namespace quickwork {

namespace {

thread_local std::chrono::steady_clock::time_point g_start_time;
thread_local uint32_t g_max_cpu_time_ms = 5000;

int interrupt_handler(JSRuntime* /*rt*/, void* /*opaque*/) {
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - g_start_time);
    return elapsed.count() > g_max_cpu_time_ms ? 1 : 0;
}

}  // namespace

// JsRuntime implementation
JsRuntime::JsRuntime(const Config& config) : config_(config) {
    rt_ = JS_NewRuntime();
    if (!rt_) {
        throw std::runtime_error("Failed to create QuickJS runtime");
    }

    JS_SetMemoryLimit(rt_, config_.get_max_memory_bytes());
    JS_SetMaxStackSize(rt_, 256 * 1024);  // 256KB stack
    JS_SetInterruptHandler(rt_, interrupt_handler, nullptr);
}

JsRuntime::~JsRuntime() {
    if (rt_) {
        JS_FreeRuntime(rt_);
    }
}

JsContext JsRuntime::create_context() {
    return JsContext(rt_, config_);
}

// JsContext implementation
JsContext::JsContext(JSRuntime* rt, const Config& config) : config_(config) {
    ctx_ = JS_NewContext(rt);
    if (!ctx_) {
        throw std::runtime_error("Failed to create QuickJS context");
    }

    start_time_ = std::chrono::steady_clock::now();
    g_start_time = start_time_;
    g_max_cpu_time_ms = config_.max_cpu_time_ms;

    setup_bindings();
}

JsContext::~JsContext() {
    if (ctx_) {
        JS_FreeContext(ctx_);
    }
}

JsContext::JsContext(JsContext&& other) noexcept
    : ctx_(other.ctx_)
    , config_(other.config_)
    , start_time_(other.start_time_)
    , has_error_(other.has_error_)
    , error_message_(std::move(other.error_message_))
{
    other.ctx_ = nullptr;
}

JsContext& JsContext::operator=(JsContext&& other) noexcept {
    if (this != &other) {
        if (ctx_) {
            JS_FreeContext(ctx_);
        }
        ctx_ = other.ctx_;
        start_time_ = other.start_time_;
        has_error_ = other.has_error_;
        error_message_ = std::move(other.error_message_);
        other.ctx_ = nullptr;
    }
    return *this;
}

void JsContext::setup_bindings() {
    bindings::setup_console(ctx_);
    bindings::setup_request_class(ctx_);
    bindings::setup_response_class(ctx_);
}

void JsContext::handle_exception() {
    JSValue exception = JS_GetException(ctx_);
    if (JS_IsNull(exception) || JS_IsUndefined(exception)) {
        error_message_ = "Unknown error";
        has_error_ = true;
        return;
    }

    JSValue message = JS_GetPropertyStr(ctx_, exception, "message");
    JSValue stack = JS_GetPropertyStr(ctx_, exception, "stack");

    std::ostringstream oss;

    if (!JS_IsUndefined(message)) {
        const char* msg_str = JS_ToCString(ctx_, message);
        if (msg_str) {
            oss << msg_str;
            JS_FreeCString(ctx_, msg_str);
        }
    } else {
        const char* exc_str = JS_ToCString(ctx_, exception);
        if (exc_str) {
            oss << exc_str;
            JS_FreeCString(ctx_, exc_str);
        }
    }

    if (!JS_IsUndefined(stack)) {
        const char* stack_str = JS_ToCString(ctx_, stack);
        if (stack_str) {
            oss << "\nStack trace:\n" << stack_str;
            JS_FreeCString(ctx_, stack_str);
        }
    }

    JS_FreeValue(ctx_, message);
    JS_FreeValue(ctx_, stack);
    JS_FreeValue(ctx_, exception);

    error_message_ = oss.str();
    has_error_ = true;
}

std::optional<HttpResponse> JsContext::extract_response(JSValue val) {
    if (JS_IsException(val)) {
        handle_exception();
        return std::nullopt;
    }

    // Check if it's a Promise
    if (JS_IsObject(val)) {
        JSValue then_val = JS_GetPropertyStr(ctx_, val, "then");
        bool is_promise = JS_IsFunction(ctx_, then_val);
        JS_FreeValue(ctx_, then_val);

        if (is_promise) {
            auto result = await_promise(val);
            JS_FreeValue(ctx_, val);
            return result;
        }
    }

    // Extract Response object
    HttpResponse response;

    // Get status
    JSValue status_val = JS_GetPropertyStr(ctx_, val, "status");
    if (JS_IsNumber(status_val)) {
        int32_t status;
        JS_ToInt32(ctx_, &status, status_val);
        response.status = status;
    }
    JS_FreeValue(ctx_, status_val);

    // Get body
    JSValue body_val = JS_GetPropertyStr(ctx_, val, "body");
    if (!JS_IsUndefined(body_val)) {
        const char* body_str = JS_ToCString(ctx_, body_val);
        if (body_str) {
            response.body = body_str;
            JS_FreeCString(ctx_, body_str);
        }
    }
    JS_FreeValue(ctx_, body_val);

    // Get headers
    JSValue headers_val = JS_GetPropertyStr(ctx_, val, "headers");
    if (JS_IsObject(headers_val)) {
        JSPropertyEnum* props = nullptr;
        uint32_t prop_count = 0;

        if (JS_GetOwnPropertyNames(ctx_, &props, &prop_count, headers_val,
                                   JS_GPN_STRING_MASK | JS_GPN_ENUM_ONLY) == 0) {
            for (uint32_t i = 0; i < prop_count; i++) {
                JSAtom atom = props[i].atom;
                const char* key = JS_AtomToCString(ctx_, atom);
                if (key) {
                    JSValue val_prop = JS_GetProperty(ctx_, headers_val, atom);
                    const char* val_str = JS_ToCString(ctx_, val_prop);
                    if (val_str) {
                        response.headers[key] = val_str;
                        JS_FreeCString(ctx_, val_str);
                    }
                    JS_FreeValue(ctx_, val_prop);
                    JS_FreeCString(ctx_, key);
                }
            }

            for (uint32_t i = 0; i < prop_count; i++) {
                JS_FreeAtom(ctx_, props[i].atom);
            }
            js_free(ctx_, props);
        }
    }
    JS_FreeValue(ctx_, headers_val);
    JS_FreeValue(ctx_, val);

    return response;
}

std::optional<HttpResponse> JsContext::await_promise(JSValue promise) {
    JSContext* ctx_ptr = nullptr;
    int ret;

    while (true) {
        ret = JS_ExecutePendingJob(JS_GetRuntime(ctx_), &ctx_ptr);
        if (ret < 0) {
            handle_exception();
            return std::nullopt;
        }
        if (ret == 0) {
            break;
        }

        // Check timeout
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time_);
        if (elapsed.count() > static_cast<int64_t>(config_.max_cpu_time_ms)) {
            error_message_ = "Execution timeout";
            has_error_ = true;
            return std::nullopt;
        }
    }

    // Get promise result
    JSPromiseStateEnum state = JS_PromiseState(ctx_, promise);

    if (state == JS_PROMISE_FULFILLED) {
        JSValue result = JS_PromiseResult(ctx_, promise);
        if (JS_IsException(result)) {
            handle_exception();
            JS_FreeValue(ctx_, result);
            return std::nullopt;
        }
        return extract_response(result);
    } else if (state == JS_PROMISE_REJECTED) {
        JSValue reason = JS_PromiseResult(ctx_, promise);
        const char* err_str = JS_ToCString(ctx_, reason);
        if (err_str) {
            error_message_ = err_str;
            JS_FreeCString(ctx_, err_str);
        } else {
            error_message_ = "Promise rejected";
        }
        JS_FreeValue(ctx_, reason);
        has_error_ = true;
        return std::nullopt;
    } else {
        error_message_ = "Promise did not resolve";
        has_error_ = true;
        return std::nullopt;
    }
}

std::optional<HttpResponse> JsContext::execute_handler(
    std::string_view source,
    const HttpRequest& request)
{
    // Create request object and set it globally
    JSValue global = JS_GetGlobalObject(ctx_);
    JSValue request_obj = bindings::create_request(ctx_, request);
    JS_SetPropertyStr(ctx_, global, "__request__", request_obj);
    JS_FreeValue(ctx_, global);

    // Transform "export default" to a form QuickJS can handle
    std::string source_str(source);
    
    // Replace "export default function" with assignment
    std::string transformed = source_str;
    size_t pos = transformed.find("export default function");
    if (pos != std::string::npos) {
        transformed.replace(pos, 23, "__handler__ = function");
    } else {
        pos = transformed.find("export default async function");
        if (pos != std::string::npos) {
            transformed.replace(pos, 29, "__handler__ = async function");
        } else {
            pos = transformed.find("export default");
            if (pos != std::string::npos) {
                transformed.replace(pos, 14, "__handler__ =");
            }
        }
    }

    // First, evaluate the handler definition
    std::string setup_code = "var __handler__;\n" + transformed;
    JSValue setup_result = JS_Eval(ctx_, setup_code.c_str(), setup_code.size(),
                                   "<handler-setup>", JS_EVAL_TYPE_GLOBAL);
    
    if (JS_IsException(setup_result)) {
        handle_exception();
        return std::nullopt;
    }
    JS_FreeValue(ctx_, setup_result);

    // Then call the handler
    std::string call_code = R"(
        (function() {
            if (typeof __handler__ !== 'function') {
                throw new Error('Handler must export a default function');
            }
            return __handler__(__request__);
        })()
    )";

    JSValue result = JS_Eval(ctx_, call_code.c_str(), call_code.size(),
                             "<handler-call>", JS_EVAL_TYPE_GLOBAL);

    if (JS_IsException(result)) {
        handle_exception();
        return std::nullopt;
    }

    return extract_response(result);
}

}  // namespace quickwork
