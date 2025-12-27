#include "handler_store.hpp"
#include "module_resolver.hpp"

#include <algorithm>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>

#include <openssl/sha.h>

extern "C" {
#include "quickjs.h"
}

namespace quickwork {

// ============================================================================
// LRUCache implementation
// ============================================================================

LRUCache::LRUCache(size_t capacity) : capacity_(capacity) {}

std::optional<Bytecode> LRUCache::get(const std::string& key) {
    std::unique_lock lock(mutex_);
    
    auto it = index_.find(key);
    if (it == index_.end()) {
        return std::nullopt;
    }
    
    // Move to front (most recently used)
    items_.splice(items_.begin(), items_, it->second);
    return it->second->second;
}

void LRUCache::put(const std::string& key, Bytecode value) {
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
    , max_storage_bytes_(config.get_max_cache_storage_bytes())
{
    ensure_cache_dir();
}

void HandlerStore::ensure_cache_dir() const {
    std::filesystem::create_directories(cache_dir_);
}

size_t HandlerStore::calculate_cache_size() const {
    size_t total_size = 0;
    for (const auto& entry : std::filesystem::directory_iterator(cache_dir_)) {
        if (entry.is_regular_file() && entry.path().extension() == ".qjbc") {
            total_size += entry.file_size();
        }
    }
    return total_size;
}

void HandlerStore::enforce_storage_limit(size_t incoming_size) {
    if (max_storage_bytes_ == 0) {
        return;  // No limit
    }

    size_t current_size = calculate_cache_size();
    
    // Check if we need to free space
    // Target: free 10% extra space to avoid frequent evictions
    size_t target_size = max_storage_bytes_ * 90 / 100;
    
    if (current_size + incoming_size <= max_storage_bytes_) {
        return;  // Enough space
    }

    // Collect all bytecode files with their modification times
    struct FileInfo {
        std::filesystem::path path;
        std::filesystem::file_time_type mtime;
        size_t size;
    };
    std::vector<FileInfo> files;

    for (const auto& entry : std::filesystem::directory_iterator(cache_dir_)) {
        if (entry.is_regular_file() && entry.path().extension() == ".qjbc") {
            files.push_back({
                entry.path(),
                entry.last_write_time(),
                entry.file_size()
            });
        }
    }

    // Sort by modification time (oldest first)
    std::sort(files.begin(), files.end(), [](const FileInfo& a, const FileInfo& b) {
        return a.mtime < b.mtime;
    });

    // Delete oldest files until we have enough space
    size_t space_needed = (current_size + incoming_size) - target_size;
    size_t freed = 0;

    for (const auto& file : files) {
        if (freed >= space_needed) {
            break;
        }
        
        std::error_code ec;
        std::filesystem::remove(file.path, ec);
        if (!ec) {
            freed += file.size;
        }
    }
}

std::string HandlerStore::compute_hash(std::string_view source) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(source.data()),
           source.size(), hash);

    // Use first 16 bytes (32 hex chars) for handler IDs
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (int i = 0; i < 16; i++) {
        oss << std::setw(2) << static_cast<int>(hash[i]);
    }
    return oss.str();
}

std::filesystem::path HandlerStore::get_handler_path(std::string_view id) const {
    return cache_dir_ / (std::string(id) + ".qjbc");
}

Bytecode HandlerStore::compile_to_bytecode(::JSRuntime* rt, std::string_view source) {
    // CRITICAL: Update stack top for current thread. The runtime was created on
    // a different thread (main), but compilation happens on HTTP handler threads.
    // Without this, QuickJS's stack overflow check fails because it compares
    // against the wrong stack base.
    JS_UpdateStackTop(rt);
    
    // Create a temporary context for compilation
    JSContext* ctx = JS_NewContext(rt);
    if (!ctx) {
        throw std::runtime_error("Failed to create context for bytecode compilation");
    }

    // Resolve and bundle ESM imports
    ModuleResolver resolver;
    std::string bundled_source;
    try {
        bundled_source = resolver.resolve_and_bundle(source);
    } catch (const std::exception& e) {
        JS_FreeContext(ctx);
        throw std::runtime_error(std::string("Module resolution failed: ") + e.what());
    }

    // Transform "export default" to a form QuickJS can handle
    std::string transformed = bundled_source;
    
    size_t pos = transformed.find("export default function");
    if (pos != std::string::npos) {
        transformed.replace(pos, 23, "__handler__ = function");
    } else {
        pos = transformed.find("export default async function");
        if (pos != std::string::npos) {
            transformed.replace(pos, 29, "__handler__ = async function");
        } else {
            pos = transformed.find("export default");
            if (pos != std::string::npos) {
                transformed.replace(pos, 14, "__handler__ =");
            }
        }
    }

    // Prepend variable declaration
    std::string setup_code = "var __handler__;\n" + transformed;

    // Compile to bytecode (JS_EVAL_FLAG_COMPILE_ONLY returns function object without executing)
    JSValue obj = JS_Eval(ctx, setup_code.c_str(), setup_code.size(),
                          "<handler>", JS_EVAL_TYPE_GLOBAL | JS_EVAL_FLAG_COMPILE_ONLY);

    if (JS_IsException(obj)) {
        JSValue exc = JS_GetException(ctx);
        std::ostringstream error_oss;
        
        const char* err_str = JS_ToCString(ctx, exc);
        if (err_str) {
            error_oss << err_str;
            JS_FreeCString(ctx, err_str);
        }
        
        // Also get stack trace if available
        JSValue stack = JS_GetPropertyStr(ctx, exc, "stack");
        if (!JS_IsUndefined(stack)) {
            const char* stack_str = JS_ToCString(ctx, stack);
            if (stack_str) {
                error_oss << "\nStack: " << stack_str;
                JS_FreeCString(ctx, stack_str);
            }
        }
        
        JS_FreeValue(ctx, stack);
        JS_FreeValue(ctx, exc);
        JS_FreeContext(ctx);
        
        std::string error_msg = error_oss.str();
        if (error_msg.empty()) error_msg = "Unknown compilation error";
        throw std::runtime_error("Failed to compile handler: " + error_msg);
    }

    // Write object to bytecode
    size_t bytecode_len = 0;
    uint8_t* bytecode_buf = JS_WriteObject(ctx, &bytecode_len, obj, JS_WRITE_OBJ_BYTECODE);
    
    JS_FreeValue(ctx, obj);
    JS_FreeContext(ctx);

    if (!bytecode_buf) {
        throw std::runtime_error("Failed to serialize bytecode");
    }

    // Copy to Bytecode struct
    Bytecode bc;
    bc.data.assign(bytecode_buf, bytecode_buf + bytecode_len);
    js_free_rt(rt, bytecode_buf);

    return bc;
}

std::string HandlerStore::store(::JSRuntime* rt, std::string_view source) {
    std::string id = compute_hash(source);

    // Check cache first
    if (cache_.contains(id)) {
        return id;
    }

    // Check if bytecode file exists on disk
    auto path = get_handler_path(id);
    if (std::filesystem::exists(path)) {
        // Load from disk and cache
        std::ifstream file(path, std::ios::binary | std::ios::ate);
        if (file) {
            auto size = file.tellg();
            file.seekg(0);
            
            Bytecode bc;
            bc.data.resize(static_cast<size_t>(size));
            file.read(reinterpret_cast<char*>(bc.data.data()), size);
            
            cache_.put(id, std::move(bc));
            return id;
        }
    }

    // Compile to bytecode
    Bytecode bc = compile_to_bytecode(rt, source);

    // Enforce storage limit before writing (deletes oldest files if needed)
    enforce_storage_limit(bc.size());

    // Write bytecode to disk
    std::ofstream file(path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Failed to write bytecode to disk: " + path.string());
    }
    file.write(reinterpret_cast<const char*>(bc.data.data()),
               static_cast<std::streamsize>(bc.data.size()));
    file.close();

    // Cache in memory
    cache_.put(id, std::move(bc));

    return id;
}

std::optional<Bytecode> HandlerStore::load(std::string_view id) {
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

    Bytecode bc;
    bc.data.resize(static_cast<size_t>(size));
    file.read(reinterpret_cast<char*>(bc.data.data()), size);

    // Cache it
    cache_.put(id_str, bc);

    return bc;
}

bool HandlerStore::exists(std::string_view id) const {
    if (cache_.contains(std::string(id))) {
        return true;
    }

    return std::filesystem::exists(get_handler_path(id));
}

}  // namespace quickwork
