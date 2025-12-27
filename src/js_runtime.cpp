#include "js_runtime.hpp"
#include "handler_store.hpp"
#include "js_bindings.hpp"

#include <chrono>
#include <cstring>
#include <sstream>
#include <stdexcept>
#include <thread>

#include <sys/resource.h>

#if defined(__APPLE__)
#include <mach/mach.h>
#include <mach/thread_info.h>
#endif

namespace quickwork {

namespace {

thread_local std::chrono::steady_clock::time_point g_start_time;
thread_local uint32_t g_max_cpu_time_ms = 5000;
thread_local double g_start_cpu_time_ms = 0.0;

// Get current thread CPU time (user + system) in milliseconds
double get_thread_cpu_time_ms() {
#if defined(__APPLE__)
    // macOS: use thread_info for per-thread CPU time
    mach_port_t thread_port = mach_thread_self();
    thread_basic_info_data_t info;
    mach_msg_type_number_t count = THREAD_BASIC_INFO_COUNT;
    kern_return_t kr = thread_info(thread_port, THREAD_BASIC_INFO, 
                                   reinterpret_cast<thread_info_t>(&info), &count);
    mach_port_deallocate(mach_task_self(), thread_port);
    
    if (kr == KERN_SUCCESS) {
        double user_ms = info.user_time.seconds * 1000.0 + info.user_time.microseconds / 1000.0;
        double sys_ms = info.system_time.seconds * 1000.0 + info.system_time.microseconds / 1000.0;
        return user_ms + sys_ms;
    }
    return 0.0;
#elif defined(__linux__)
    // Linux: use RUSAGE_THREAD
    struct rusage usage;
    if (getrusage(RUSAGE_THREAD, &usage) == 0) {
        double user_ms = usage.ru_utime.tv_sec * 1000.0 + usage.ru_utime.tv_usec / 1000.0;
        double sys_ms = usage.ru_stime.tv_sec * 1000.0 + usage.ru_stime.tv_usec / 1000.0;
        return user_ms + sys_ms;
    }
    return 0.0;
#else
    // Fallback: use process-wide CPU time (less accurate)
    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage) == 0) {
        double user_ms = usage.ru_utime.tv_sec * 1000.0 + usage.ru_utime.tv_usec / 1000.0;
        double sys_ms = usage.ru_stime.tv_sec * 1000.0 + usage.ru_stime.tv_usec / 1000.0;
        return user_ms + sys_ms;
    }
    return 0.0;
#endif
}

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
    // Don't set stack size - let QuickJS auto-detect
    // JS_SetMaxStackSize can cause issues on musl/Alpine
    JS_SetInterruptHandler(rt_, interrupt_handler, nullptr);
}

JsRuntime::~JsRuntime() {
    if (rt_) {
        JS_FreeRuntime(rt_);
    }
}

JsContext JsRuntime::create_context() {
    // Update stack top for the current thread - worker threads have different
    // stack addresses than the thread where the runtime was created
    JS_UpdateStackTop(rt_);
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
    g_start_cpu_time_ms = get_thread_cpu_time_ms();
    g_max_cpu_time_ms = config_.max_cpu_time_ms;

    setup_bindings();
}

JsContext::~JsContext() {
    if (ctx_) {
        bindings::cleanup_timers(ctx_);
        bindings::cleanup_pending_fetches(ctx_);
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
    bindings::setup_crypto(ctx_);
    bindings::setup_request_class(ctx_);
    bindings::setup_response_class(ctx_);
    bindings::setup_stream_response_class(ctx_);
    bindings::setup_fetch(ctx_);
    bindings::setup_text_decoder(ctx_);
    bindings::setup_timers(ctx_);
    bindings::setup_kv_module(ctx_);
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
        // Execute pending JS jobs (microtasks)
        ret = JS_ExecutePendingJob(JS_GetRuntime(ctx_), &ctx_ptr);
        if (ret < 0) {
            handle_exception();
            return std::nullopt;
        }
        
        // Process any expired timers
        bool timer_fired = bindings::process_timers(ctx_);
        
        // Process any pending fetch operations
        bool fetch_processed = bindings::process_pending_fetches(ctx_);
        
        // If no jobs, no timers fired, and no fetches processed, check if we should continue waiting
        if (ret == 0 && !timer_fired && !fetch_processed) {
            // Check if there are pending timers or fetches we need to wait for
            if (!bindings::has_pending_timers(ctx_) && !bindings::has_pending_fetches(ctx_)) {
                break;
            }
            // Small sleep to avoid busy-waiting
            std::this_thread::sleep_for(std::chrono::microseconds(100));
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

ExecutionResult JsContext::execute_handler(
    const Bytecode& bytecode,
    const HttpRequest& request)
{
    ExecutionResult exec_result;
    
    // Create request object and set it globally
    JSValue global = JS_GetGlobalObject(ctx_);
    JSValue request_obj = bindings::create_request(ctx_, request);
    JS_SetPropertyStr(ctx_, global, "__request__", request_obj);
    JS_FreeValue(ctx_, global);

    // Load bytecode - this returns the compiled function object
    JSValue obj = JS_ReadObject(ctx_, bytecode.ptr(), bytecode.size(), JS_READ_OBJ_BYTECODE);
    
    if (JS_IsException(obj)) {
        handle_exception();
        exec_result.error = error_message_;
        return exec_result;
    }

    // Evaluate the loaded bytecode (executes the compiled script, setting up __handler__)
    JSValue setup_result = JS_EvalFunction(ctx_, obj);
    
    if (JS_IsException(setup_result)) {
        handle_exception();
        exec_result.error = error_message_;
        return exec_result;
    }
    JS_FreeValue(ctx_, setup_result);

    // Call the handler
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
        exec_result.error = error_message_;
        return exec_result;
    }

    exec_result.response = extract_response(result);
    
    // Collect stats - use actual CPU time, not wall-clock time
    double end_cpu_time_ms = get_thread_cpu_time_ms();
    exec_result.stats.cpu_time_ms = end_cpu_time_ms - g_start_cpu_time_ms;
    
    JSMemoryUsage mem_usage;
    JS_ComputeMemoryUsage(JS_GetRuntime(ctx_), &mem_usage);
    exec_result.stats.memory_used = static_cast<size_t>(mem_usage.memory_used_size);
    
    if (!exec_result.response) {
        exec_result.error = error_message_;
    }
    
    return exec_result;
}

}  // namespace quickwork
