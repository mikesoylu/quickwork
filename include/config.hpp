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
    uint32_t max_cpu_time_ms = 5000;
    size_t thread_count = 0;  // 0 = hardware concurrency
    size_t handler_cache_size = 1024;  // Max handlers in memory cache
    size_t max_cache_storage_mb = 0;  // Max disk storage for bytecode cache (0 = unlimited)

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
