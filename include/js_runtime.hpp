#pragma once

#include "config.hpp"

#include <atomic>
#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

extern "C" {
#include "quickjs.h"
}

namespace quickwork {

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

    [[nodiscard]] ExecutionResult execute_handler(
        std::string_view source,
        const HttpRequest& request
    );

    [[nodiscard]] JSContext* get() const noexcept { return ctx_; }
    [[nodiscard]] JSRuntime* runtime() const noexcept { return JS_GetRuntime(ctx_); }
    [[nodiscard]] bool has_error() const noexcept { return has_error_; }
    [[nodiscard]] const std::string& get_error() const noexcept { return error_message_; }

private:
    void setup_bindings();
    void setup_interrupt_handler();
    [[nodiscard]] std::optional<HttpResponse> extract_response(JSValue val);
    [[nodiscard]] std::optional<HttpResponse> await_promise(JSValue promise);
    void handle_exception();

    JSContext* ctx_ = nullptr;
    const Config& config_;
    std::chrono::steady_clock::time_point start_time_;
    bool has_error_ = false;
    std::string error_message_;
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
