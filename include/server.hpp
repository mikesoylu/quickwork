#pragma once

#include "config.hpp"
#include "handler_store.hpp"
#include "js_runtime.hpp"
#include "thread_pool.hpp"

#include <memory>
#include <mutex>
#include <string>

namespace quickwork {

class Server {
public:
    explicit Server(const Config& config);
    ~Server();

    Server(const Server&) = delete;
    Server& operator=(const Server&) = delete;
    Server(Server&&) = delete;
    Server& operator=(Server&&) = delete;

    void run();
    void stop();

    // Store handler source and return ID (thread-safe, compiles to bytecode)
    [[nodiscard]] std::string store_handler(std::string_view source);

private:
    Config config_;
    std::unique_ptr<JsRuntime> compiler_runtime_;  // Dedicated runtime for bytecode compilation
    std::mutex compiler_mutex_;                     // Protect compiler_runtime_ access
    std::unique_ptr<HandlerStore> handler_store_;
    std::unique_ptr<ThreadPool> thread_pool_;
    bool running_ = false;
};

}  // namespace quickwork
