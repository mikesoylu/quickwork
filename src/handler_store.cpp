#include "handler_store.hpp"

#include <fstream>
#include <iomanip>
#include <sstream>

#include <openssl/sha.h>

namespace quickwork {

// ============================================================================
// LRUCache implementation
// ============================================================================

LRUCache::LRUCache(size_t capacity) : capacity_(capacity) {}

std::optional<std::string> LRUCache::get(const std::string& key) {
    std::unique_lock lock(mutex_);
    
    auto it = index_.find(key);
    if (it == index_.end()) {
        return std::nullopt;
    }
    
    // Move to front (most recently used)
    items_.splice(items_.begin(), items_, it->second);
    return it->second->second;
}

void LRUCache::put(const std::string& key, std::string value) {
    std::unique_lock lock(mutex_);
    
    auto it = index_.find(key);
    if (it != index_.end()) {
        // Update existing and move to front
        it->second->second = std::move(value);
        items_.splice(items_.begin(), items_, it->second);
        return;
    }
    
    // Evict least recently used if at capacity
    if (items_.size() >= capacity_) {
        auto& lru = items_.back();
        index_.erase(lru.first);
        items_.pop_back();
    }
    
    // Insert new item at front
    items_.emplace_front(key, std::move(value));
    index_[key] = items_.begin();
}

bool LRUCache::contains(const std::string& key) const {
    std::shared_lock lock(mutex_);
    return index_.find(key) != index_.end();
}

size_t LRUCache::size() const {
    std::shared_lock lock(mutex_);
    return items_.size();
}

// ============================================================================
// HandlerStore implementation
// ============================================================================

HandlerStore::HandlerStore(const Config& config)
    : cache_dir_(config.cache_dir)
    , cache_(config.handler_cache_size)
{
    ensure_cache_dir();
}

void HandlerStore::ensure_cache_dir() const {
    std::filesystem::create_directories(cache_dir_);
}

std::string HandlerStore::compute_hash(std::string_view source) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(source.data()),
           source.size(), hash);

    // Use first 8 bytes (16 hex chars) for shorter IDs
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (int i = 0; i < 8; i++) {
        oss << std::setw(2) << static_cast<int>(hash[i]);
    }
    return oss.str();
}

std::filesystem::path HandlerStore::get_handler_path(std::string_view id) const {
    return cache_dir_ / (std::string(id) + ".js");
}

std::string HandlerStore::store(std::string_view source) {
    std::string id = compute_hash(source);

    // Check cache first
    if (cache_.contains(id)) {
        return id;
    }

    // Write to disk
    auto path = get_handler_path(id);
    if (!std::filesystem::exists(path)) {
        std::ofstream file(path, std::ios::binary);
        if (!file) {
            throw std::runtime_error("Failed to write handler to disk: " + path.string());
        }
        file.write(source.data(), static_cast<std::streamsize>(source.size()));
        file.close();
    }

    // Cache in memory
    cache_.put(id, std::string(source));

    return id;
}

std::optional<std::string> HandlerStore::load(std::string_view id) {
    std::string id_str(id);
    
    // Try cache first (also updates LRU order)
    auto cached = cache_.get(id_str);
    if (cached) {
        return cached;
    }

    // Try loading from disk
    auto path = get_handler_path(id);
    if (!std::filesystem::exists(path)) {
        return std::nullopt;
    }

    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) {
        return std::nullopt;
    }

    auto size = file.tellg();
    file.seekg(0);

    std::string content(static_cast<size_t>(size), '\0');
    file.read(content.data(), size);

    // Cache it
    cache_.put(id_str, content);

    return content;
}

bool HandlerStore::exists(std::string_view id) const {
    if (cache_.contains(std::string(id))) {
        return true;
    }

    return std::filesystem::exists(get_handler_path(id));
}

}  // namespace quickwork
