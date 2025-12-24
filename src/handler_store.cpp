#include "handler_store.hpp"

#include <fstream>
#include <iomanip>
#include <sstream>

#include <openssl/sha.h>

namespace quickwork {

HandlerStore::HandlerStore(const Config& config)
    : cache_dir_(config.cache_dir)
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

    {
        std::shared_lock lock(mutex_);
        if (cache_.contains(id)) {
            return id;
        }
    }

    std::unique_lock lock(mutex_);

    // Double-check after acquiring exclusive lock
    if (cache_.contains(id)) {
        return id;
    }

    // Write to disk
    auto path = get_handler_path(id);
    std::ofstream file(path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Failed to write handler to disk: " + path.string());
    }
    file.write(source.data(), static_cast<std::streamsize>(source.size()));
    file.close();

    // Cache in memory
    cache_[id] = std::string(source);

    return id;
}

std::optional<std::string> HandlerStore::load(std::string_view id) const {
    {
        std::shared_lock lock(mutex_);
        auto it = cache_.find(std::string(id));
        if (it != cache_.end()) {
            return it->second;
        }
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
    {
        std::unique_lock lock(mutex_);
        cache_[std::string(id)] = content;
    }

    return content;
}

bool HandlerStore::exists(std::string_view id) const {
    {
        std::shared_lock lock(mutex_);
        if (cache_.contains(std::string(id))) {
            return true;
        }
    }

    return std::filesystem::exists(get_handler_path(id));
}

}  // namespace quickwork
