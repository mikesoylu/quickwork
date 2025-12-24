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

    [[nodiscard]] size_t get_thread_count() const noexcept {
        return thread_count == 0 ? std::thread::hardware_concurrency() : thread_count;
    }

    [[nodiscard]] size_t get_max_memory_bytes() const noexcept {
        return max_memory_mb * 1024 * 1024;
    }
};

}  // namespace quickwork
