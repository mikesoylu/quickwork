#include "kv_store.hpp"

#include <algorithm>

namespace quickwork {

// Static member definitions
std::unique_ptr<KvStore> KvStore::instance_;
std::once_flag KvStore::init_flag_;

KvStore::KvStore(size_t max_entries) : max_entries_(max_entries) {
    store_.reserve(max_entries);
}

void KvStore::init(size_t max_entries) {
    std::call_once(init_flag_, [max_entries]() {
        instance_ = std::make_unique<KvStore>(max_entries);
    });
}

KvStore& KvStore::instance() {
    // Default initialization if not explicitly initialized
    std::call_once(init_flag_, []() {
        instance_ = std::make_unique<KvStore>(10 * 1024);
    });
    return *instance_;
}

bool KvStore::is_expired(const Entry& entry) const {
    if (!entry.has_ttl) {
        return false;
    }
    return Clock::now() >= entry.expires_at;
}

void KvStore::touch(const std::string& key, Entry& entry) {
    // Move to front of LRU list
    lru_list_.erase(entry.lru_it);
    lru_list_.push_front(key);
    entry.lru_it = lru_list_.begin();
}

void KvStore::evict_expired() {
    auto now = Clock::now();
    auto it = store_.begin();
    while (it != store_.end()) {
        if (it->second.has_ttl && now >= it->second.expires_at) {
            lru_list_.erase(it->second.lru_it);
            it = store_.erase(it);
        } else {
            ++it;
        }
    }
}

void KvStore::evict_lru() {
    // Remove from the back (least recently used)
    while (store_.size() >= max_entries_ && !lru_list_.empty()) {
        const std::string& key = lru_list_.back();
        store_.erase(key);
        lru_list_.pop_back();
    }
}

bool KvStore::set(const std::string& key, const std::string& value, uint64_t ttl_ms) {
    // Check size limits before acquiring lock
    if (key.size() > KvStore::MAX_KEY_SIZE || value.size() > KvStore::MAX_VALUE_SIZE) {
        return false;
    }

    std::unique_lock lock(mutex_);

    // Check if key already exists
    auto it = store_.find(key);
    if (it != store_.end()) {
        // Update existing entry
        it->second.value = value;
        if (ttl_ms > 0) {
            it->second.has_ttl = true;
            it->second.expires_at = Clock::now() + std::chrono::milliseconds(ttl_ms);
        } else {
            it->second.has_ttl = false;
        }
        touch(key, it->second);
        return true;
    }

    // Need to make room for new entry
    if (store_.size() >= max_entries_) {
        // First try to evict expired entries
        evict_expired();
        // If still full, evict LRU
        if (store_.size() >= max_entries_) {
            evict_lru();
        }
    }

    // Insert new entry
    Entry entry;
    entry.value = value;
    if (ttl_ms > 0) {
        entry.has_ttl = true;
        entry.expires_at = Clock::now() + std::chrono::milliseconds(ttl_ms);
    }

    lru_list_.push_front(key);
    entry.lru_it = lru_list_.begin();
    store_.emplace(key, std::move(entry));
    return true;
}

std::optional<std::string> KvStore::get(const std::string& key) {
    std::unique_lock lock(mutex_);

    auto it = store_.find(key);
    if (it == store_.end()) {
        return std::nullopt;
    }

    // Check expiration
    if (is_expired(it->second)) {
        lru_list_.erase(it->second.lru_it);
        store_.erase(it);
        return std::nullopt;
    }

    // Update LRU
    touch(key, it->second);
    return it->second.value;
}

bool KvStore::del(const std::string& key) {
    std::unique_lock lock(mutex_);

    auto it = store_.find(key);
    if (it == store_.end()) {
        return false;
    }

    lru_list_.erase(it->second.lru_it);
    store_.erase(it);
    return true;
}

bool KvStore::exists(const std::string& key) {
    std::shared_lock lock(mutex_);

    auto it = store_.find(key);
    if (it == store_.end()) {
        return false;
    }

    // Check expiration (but don't delete - we only have shared lock)
    return !is_expired(it->second);
}

std::optional<uint64_t> KvStore::ttl(const std::string& key) {
    std::shared_lock lock(mutex_);

    auto it = store_.find(key);
    if (it == store_.end()) {
        return std::nullopt;
    }

    if (!it->second.has_ttl) {
        return std::nullopt;  // No TTL set
    }

    if (is_expired(it->second)) {
        return std::nullopt;  // Expired
    }

    auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
        it->second.expires_at - Clock::now());
    return static_cast<uint64_t>(remaining.count());
}

std::vector<std::string> KvStore::scan(const std::string& prefix, size_t limit) {
    std::shared_lock lock(mutex_);

    std::vector<std::string> results;
    results.reserve(std::min(limit, store_.size()));

    auto now = Clock::now();
    for (const auto& [key, entry] : store_) {
        if (results.size() >= limit) {
            break;
        }

        // Check prefix match
        if (key.size() >= prefix.size() &&
            key.compare(0, prefix.size(), prefix) == 0) {
            // Skip expired entries
            if (entry.has_ttl && now >= entry.expires_at) {
                continue;
            }
            results.push_back(key);
        }
    }

    return results;
}

std::vector<std::pair<std::string, std::string>> KvStore::scan_pairs(
    const std::string& prefix, size_t limit) {
    std::shared_lock lock(mutex_);

    std::vector<std::pair<std::string, std::string>> results;
    results.reserve(std::min(limit, store_.size()));

    auto now = Clock::now();
    for (const auto& [key, entry] : store_) {
        if (results.size() >= limit) {
            break;
        }

        // Check prefix match
        if (key.size() >= prefix.size() &&
            key.compare(0, prefix.size(), prefix) == 0) {
            // Skip expired entries
            if (entry.has_ttl && now >= entry.expires_at) {
                continue;
            }
            results.emplace_back(key, entry.value);
        }
    }

    return results;
}

size_t KvStore::size() const {
    std::shared_lock lock(mutex_);
    return store_.size();
}

void KvStore::clear() {
    std::unique_lock lock(mutex_);
    store_.clear();
    lru_list_.clear();
}

}  // namespace quickwork
