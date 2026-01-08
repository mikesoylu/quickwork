#pragma once

#include "config.hpp"
#include "handler_store.hpp"
#include "js_runtime.hpp"
#include "thread_pool.hpp"

#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <thread>

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

    // Dev mode: get the current dev handler ID (thread-safe)
    [[nodiscard]] std::string get_dev_handler_id() const;

    // Check if running in dev mode
    [[nodiscard]] bool is_dev_mode() const noexcept { return config_.dev_mode; }

    // Active request tracking for idle timeout
    void request_started();
    void request_finished();

private:
    // Idle timeout check thread function
    void idle_timeout_watcher();
    // Dev mode: reload handler from file
    void reload_dev_handler();
    
    // Dev mode: file watcher thread function
    void watch_handler_file();

    Config config_;
    std::unique_ptr<JsRuntime> compiler_runtime_;  // Dedicated runtime for bytecode compilation
    std::mutex compiler_mutex_;                     // Protect compiler_runtime_ access
    std::unique_ptr<HandlerStore> handler_store_;
    std::unique_ptr<ThreadPool> thread_pool_;
    std::atomic<bool> running_{false};

    // Dev mode state
    std::string dev_handler_id_;
    mutable std::shared_mutex dev_handler_mutex_;
    std::thread file_watcher_thread_;
    std::atomic<bool> watcher_running_{false};

    // Idle timeout state
    std::atomic<size_t> active_requests_{0};
    std::atomic<std::chrono::steady_clock::time_point> last_request_end_time_{std::chrono::steady_clock::now()};
    std::thread idle_timeout_thread_;
    std::atomic<bool> idle_watcher_running_{false};
};

}  // namespace quickwork
