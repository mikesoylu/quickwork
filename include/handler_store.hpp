#pragma once

#include "config.hpp"

#include <filesystem>
#include <list>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>

namespace quickwork {

// Thread-safe LRU cache for handler source code
class LRUCache {
public:
    explicit LRUCache(size_t capacity);

    // Returns true if found, updates value and marks as recently used
    [[nodiscard]] std::optional<std::string> get(const std::string& key);
    
    // Insert or update a key-value pair
    void put(const std::string& key, std::string value);
    
    // Check if key exists (doesn't update LRU order)
    [[nodiscard]] bool contains(const std::string& key) const;
    
    // Get current size
    [[nodiscard]] size_t size() const;

private:
    size_t capacity_;
    
    // List stores key-value pairs, front = most recent, back = least recent
    std::list<std::pair<std::string, std::string>> items_;
    
    // Map from key to iterator in the list for O(1) lookup
    std::unordered_map<std::string, std::list<std::pair<std::string, std::string>>::iterator> index_;
    
    mutable std::shared_mutex mutex_;
};

class HandlerStore {
public:
    explicit HandlerStore(const Config& config);

    [[nodiscard]] std::string store(std::string_view source);
    [[nodiscard]] std::optional<std::string> load(std::string_view id);
    [[nodiscard]] bool exists(std::string_view id) const;

private:
    [[nodiscard]] std::filesystem::path get_handler_path(std::string_view id) const;
    [[nodiscard]] static std::string compute_hash(std::string_view source);
    void ensure_cache_dir() const;

    std::filesystem::path cache_dir_;
    LRUCache cache_;
};

}  // namespace quickwork
