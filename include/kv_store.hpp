#pragma once

#include <chrono>
#include <cstddef>
#include <memory>

#include <list>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace quickwork {

// Thread-safe in-memory key-value store with LRU eviction and TTL support
class KvStore {
public:
    using Clock = std::chrono::steady_clock;
    using TimePoint = Clock::time_point;

    static constexpr size_t MAX_KEY_SIZE = 128;
    static constexpr size_t MAX_VALUE_SIZE = 1024;

    explicit KvStore(size_t max_entries = 10 * 1024);
    ~KvStore() = default;

    KvStore(const KvStore&) = delete;
    KvStore& operator=(const KvStore&) = delete;
    KvStore(KvStore&&) = delete;
    KvStore& operator=(KvStore&&) = delete;

    // Set a key-value pair with optional TTL in milliseconds (0 = no expiration)
    // Returns false if key or value exceeds size limits
    [[nodiscard]] bool set(const std::string& key, const std::string& value, uint64_t ttl_ms = 0);

    // Get a value by key, returns nullopt if not found or expired
    [[nodiscard]] std::optional<std::string> get(const std::string& key);

    // Delete a key, returns true if key existed
    bool del(const std::string& key);

    // Check if a key exists (and is not expired)
    [[nodiscard]] bool exists(const std::string& key);

    // Get remaining TTL in milliseconds, returns nullopt if no TTL or key doesn't exist
    [[nodiscard]] std::optional<uint64_t> ttl(const std::string& key);

    // Scan keys with a given prefix, returns up to limit keys
    [[nodiscard]] std::vector<std::string> scan(const std::string& prefix, size_t limit = 100);

    // Get all key-value pairs matching a prefix (for iteration)
    [[nodiscard]] std::vector<std::pair<std::string, std::string>> scan_pairs(
        const std::string& prefix, size_t limit = 100);

    // Get current number of entries
    [[nodiscard]] size_t size() const;

    // Get maximum number of entries
    [[nodiscard]] size_t max_size() const noexcept { return max_entries_; }

    // Clear all entries
    void clear();

    // Get the global KvStore instance
    [[nodiscard]] static KvStore& instance();

    // Initialize the global instance with a specific max size
    static void init(size_t max_entries);

private:
    struct Entry {
        std::string value;
        TimePoint expires_at;
        bool has_ttl = false;
        std::list<std::string>::iterator lru_it;
    };

    // Check if an entry is expired
    [[nodiscard]] bool is_expired(const Entry& entry) const;

    // Evict expired entries (called periodically)
    void evict_expired();

    // Evict LRU entries to make room
    void evict_lru();

    // Move key to front of LRU list
    void touch(const std::string& key, Entry& entry);

    mutable std::shared_mutex mutex_;
    std::unordered_map<std::string, Entry> store_;
    std::list<std::string> lru_list_;  // Front = most recently used
    size_t max_entries_;

    // Global instance
    static std::unique_ptr<KvStore> instance_;
    static std::once_flag init_flag_;
};

}  // namespace quickwork
