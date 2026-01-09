#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <thread>

namespace quickwork {

struct Config {
    std::string host = "0.0.0.0";
    uint16_t port = 8080;
    std::filesystem::path cache_dir = "./handlers";
    size_t max_memory_mb = 64;
    uint32_t max_cpu_time_ms = 5000;  // Max CPU time for JS execution
    uint32_t max_wall_time_ms = 30000;  // Max wall-clock time (for long async operations)
    size_t thread_count = 0;  // 0 = hardware concurrency
    size_t handler_cache_size = 1024;  // Max handlers in memory cache
    size_t max_cache_storage_mb = 0;  // Max disk storage for bytecode cache (0 = unlimited)
    size_t kv_max_entries = 10000;  // Max entries in the shared KV store
    uint32_t idle_timeout_seconds = 0;  // Idle timeout in seconds (0 = disabled)
    std::string deploy_token;  // Token required for deploy requests (empty = no auth)

    // Dev mode settings
    bool dev_mode = false;
    std::filesystem::path dev_handler_file;  // Handler file to watch in dev mode

    [[nodiscard]] size_t get_thread_count() const noexcept {
        return thread_count == 0 ? std::thread::hardware_concurrency() : thread_count;
    }

    [[nodiscard]] size_t get_max_memory_bytes() const noexcept {
        return max_memory_mb * 1024 * 1024;
    }

    [[nodiscard]] size_t get_max_cache_storage_bytes() const noexcept {
        return max_cache_storage_mb * 1024 * 1024;
    }
};

}  // namespace quickwork
