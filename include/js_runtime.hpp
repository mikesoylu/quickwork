#pragma once

#include "config.hpp"
#include "handler_store.hpp"

#include <chrono>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

extern "C" {
#include "quickjs.h"
}

namespace quickwork {

// Callback for writing streaming chunks to the client
// Called with empty string to signal end of stream
using StreamWriter = std::function<void(std::string_view chunk)>;

struct HttpRequest {
    std::string method;
    std::string url;
    std::string body;
    std::unordered_map<std::string, std::string> headers;
};

struct HttpResponse {
    int status = 200;
    std::string body;
    std::unordered_map<std::string, std::string> headers;
    
    // If set, response is streaming and body should be ignored
    // The handler will write directly via this callback
    StreamWriter stream_writer;
};

struct ExecutionStats {
    size_t memory_used = 0;
    double cpu_time_ms = 0.0;
};

struct ExecutionResult {
    std::optional<HttpResponse> response;
    ExecutionStats stats;
    std::string error;
};

class JsContext {
public:
    JsContext(JSRuntime* rt, const Config& config);
    ~JsContext();

    JsContext(const JsContext&) = delete;
    JsContext& operator=(const JsContext&) = delete;
    JsContext(JsContext&&) noexcept;
    JsContext& operator=(JsContext&&) noexcept;

    // Start executing a handler, returns true if result is ready immediately
    // If false, use poll() to check for completion
    [[nodiscard]] bool start_handler(
        const Bytecode& bytecode,
        const HttpRequest& request
    );

    // Poll for completion of async handler. Returns true if done.
    [[nodiscard]] bool poll();

    // Get the final result after poll() returns true or start_handler() returns true
    [[nodiscard]] ExecutionResult get_result();

    // Legacy blocking API - executes handler and blocks until complete
    [[nodiscard]] ExecutionResult execute_handler(
        const Bytecode& bytecode,
        const HttpRequest& request
    );

    [[nodiscard]] JSContext* get() const noexcept { return ctx_; }
    [[nodiscard]] JSRuntime* runtime() const noexcept { return JS_GetRuntime(ctx_); }
    [[nodiscard]] bool has_error() const noexcept { return has_error_; }
    [[nodiscard]] const std::string& get_error() const noexcept { return error_message_; }
    [[nodiscard]] bool is_pending() const noexcept { return !JS_IsUndefined(pending_promise_); }

private:
    void setup_bindings();
    void setup_interrupt_handler();
    [[nodiscard]] std::optional<HttpResponse> extract_response(JSValue val);
    [[nodiscard]] std::optional<HttpResponse> await_promise(JSValue promise);
    [[nodiscard]] bool poll_promise();  // Non-blocking promise poll
    void handle_exception();
    void finalize_result();

    JSContext* ctx_ = nullptr;
    const Config& config_;
    std::chrono::steady_clock::time_point start_time_;
    bool has_error_ = false;
    std::string error_message_;
    
    // For async execution
    JSValue pending_promise_ = JS_UNDEFINED;
    ExecutionResult pending_result_;
};

class JsRuntime {
public:
    explicit JsRuntime(const Config& config);
    ~JsRuntime();

    JsRuntime(const JsRuntime&) = delete;
    JsRuntime& operator=(const JsRuntime&) = delete;
    JsRuntime(JsRuntime&&) = delete;
    JsRuntime& operator=(JsRuntime&&) = delete;

    [[nodiscard]] JsContext create_context();
    [[nodiscard]] JSRuntime* get() const noexcept { return rt_; }

private:
    JSRuntime* rt_ = nullptr;
    const Config& config_;
};

}  // namespace quickwork
