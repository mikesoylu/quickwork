#pragma once

#include "config.hpp"

#include <cstdint>
#include <filesystem>
#include <list>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

// Forward declare JSRuntime (from QuickJS)
struct JSRuntime;

namespace quickwork {

// Bytecode representation
struct Bytecode {
    std::vector<uint8_t> data;
    
    [[nodiscard]] bool empty() const noexcept { return data.empty(); }
    [[nodiscard]] size_t size() const noexcept { return data.size(); }
    [[nodiscard]] const uint8_t* ptr() const noexcept { return data.data(); }
};

// Thread-safe LRU cache for compiled bytecode
class LRUCache {
public:
    explicit LRUCache(size_t capacity);

    // Returns bytecode if found, updates LRU order
    [[nodiscard]] std::optional<Bytecode> get(const std::string& key);
    
    // Insert or update bytecode
    void put(const std::string& key, Bytecode value);
    
    // Check if key exists (doesn't update LRU order)
    [[nodiscard]] bool contains(const std::string& key) const;
    
    // Get current size
    [[nodiscard]] size_t size() const;

private:
    size_t capacity_;
    
    // List stores key-bytecode pairs, front = most recent, back = least recent
    std::list<std::pair<std::string, Bytecode>> items_;
    
    // Map from key to iterator in the list for O(1) lookup
    std::unordered_map<std::string, std::list<std::pair<std::string, Bytecode>>::iterator> index_;
    
    mutable std::shared_mutex mutex_;
};

class HandlerStore {
public:
    explicit HandlerStore(const Config& config);

    // Compile JS source to bytecode and store it, returns handler ID
    [[nodiscard]] std::string store(::JSRuntime* rt, std::string_view source);
    
    // Load compiled bytecode by ID
    [[nodiscard]] std::optional<Bytecode> load(std::string_view id);
    
    // Check if handler exists
    [[nodiscard]] bool exists(std::string_view id) const;

private:
    [[nodiscard]] std::filesystem::path get_handler_path(std::string_view id) const;
    [[nodiscard]] static std::string compute_hash(std::string_view source);
    [[nodiscard]] static Bytecode compile_to_bytecode(::JSRuntime* rt, std::string_view source);
    void ensure_cache_dir() const;
    
    // Storage management
    [[nodiscard]] size_t calculate_cache_size() const;
    void enforce_storage_limit(size_t incoming_size);

    std::filesystem::path cache_dir_;
    LRUCache cache_;
    size_t max_storage_bytes_;  // 0 = unlimited
};

}  // namespace quickwork
