#pragma once

#include "config.hpp"

#include <filesystem>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>

namespace quickwork {

class HandlerStore {
public:
    explicit HandlerStore(const Config& config);

    [[nodiscard]] std::string store(std::string_view source);
    [[nodiscard]] std::optional<std::string> load(std::string_view id) const;
    [[nodiscard]] bool exists(std::string_view id) const;

private:
    [[nodiscard]] std::filesystem::path get_handler_path(std::string_view id) const;
    [[nodiscard]] static std::string compute_hash(std::string_view source);
    void ensure_cache_dir() const;

    std::filesystem::path cache_dir_;
    mutable std::shared_mutex mutex_;
    mutable std::unordered_map<std::string, std::string> cache_;
};

}  // namespace quickwork
