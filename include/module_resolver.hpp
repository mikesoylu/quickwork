#pragma once

#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace quickwork {

// Represents a parsed import statement
struct ImportInfo {
    std::string specifier;           // e.g., "https://esm.sh/lodash"
    std::string full_match;          // The entire import statement
    std::vector<std::string> names;  // Named imports: {a, b as c}
    std::string default_name;        // Default import name
    std::string namespace_name;      // For: import * as name
    bool is_dynamic = false;         // import() expression
    bool is_export_from = false;     // export * from / export { } from
};

// Module resolver that fetches and bundles ESM modules
class ModuleResolver {
public:
    ModuleResolver() = default;

    // Resolve all imports in source and return bundled code
    // This fetches remote modules and inlines them
    [[nodiscard]] std::string resolve_and_bundle(std::string_view source);

private:
    // Parse import statements from source
    [[nodiscard]] std::vector<ImportInfo> parse_imports(std::string_view source);
    
    // Parse imports with a base URL for resolving relative paths
    [[nodiscard]] std::vector<ImportInfo> parse_imports_with_base(std::string_view source,
                                                                    const std::string& base_url);
    
    // Fetch a module from URL (with caching)
    [[nodiscard]] std::string fetch_module(const std::string& url);
    
    // Recursively resolve imports in fetched module
    [[nodiscard]] std::string resolve_module(const std::string& url, 
                                              std::unordered_set<std::string>& visited);
    
    // Generate a unique module variable name from URL
    [[nodiscard]] static std::string url_to_var_name(const std::string& url);
    
    // Check if a specifier is a remote URL (esm.sh, etc)
    [[nodiscard]] static bool is_remote_url(const std::string& specifier);
    
    // Check if this is a Node.js polyfill path that we provide ourselves
    [[nodiscard]] static bool is_node_polyfill(const std::string& specifier);
    
    // Check if a specifier is a built-in module (quickw, etc)
    [[nodiscard]] static bool is_builtin_module(const std::string& specifier);
    
    // Transform built-in module imports to use the global module initializer
    [[nodiscard]] static std::string transform_builtin_import(const ImportInfo& imp);
    
    // Normalize URL (handle relative imports within esm.sh)
    [[nodiscard]] static std::string normalize_url(const std::string& base_url, 
                                                    const std::string& specifier);

    // Module cache: URL -> source code
    std::unordered_map<std::string, std::string> module_cache_;
};

}  // namespace quickwork
