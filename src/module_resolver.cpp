#include "module_resolver.hpp"

#include <algorithm>
#include <cctype>
#include <iostream>
#include <regex>
#include <sstream>
#include <stdexcept>

#include <curl/curl.h>

namespace quickwork {

namespace {

// CURL write callback
size_t write_callback(void* contents, size_t size, size_t nmemb, std::string* userp) {
    size_t total_size = size * nmemb;
    userp->append(static_cast<char*>(contents), total_size);
    return total_size;
}

// Simple URL parser for extracting base URL
std::string get_base_url(const std::string& url) {
    // Find the last '/' before any query string
    size_t query_pos = url.find('?');
    std::string path = (query_pos != std::string::npos) ? url.substr(0, query_pos) : url;
    
    size_t last_slash = path.rfind('/');
    if (last_slash != std::string::npos && last_slash > 8) {  // After "https://"
        return path.substr(0, last_slash + 1);
    }
    return path + "/";
}

// Extract hostname from URL
std::string get_host(const std::string& url) {
    size_t start = url.find("://");
    if (start == std::string::npos) return "";
    start += 3;
    size_t end = url.find('/', start);
    return url.substr(start, end - start);
}

}  // namespace

bool ModuleResolver::is_remote_url(const std::string& specifier) {
    return specifier.find("https://") == 0 || 
           specifier.find("http://") == 0 ||
           specifier.find("esm.sh/") == 0;
}

std::string ModuleResolver::normalize_url(const std::string& base_url, 
                                           const std::string& specifier) {
    // Handle esm.sh shorthand
    if (specifier.find("esm.sh/") == 0) {
        return "https://" + specifier;
    }
    
    // Already absolute URL
    if (specifier.find("https://") == 0 || specifier.find("http://") == 0) {
        return specifier;
    }
    
    // Absolute path from root (e.g., /uuid@9.0.1/es2022/uuid.mjs on esm.sh)
    if (!specifier.empty() && specifier[0] == '/') {
        // Get origin (scheme + host)
        size_t start = base_url.find("://");
        if (start != std::string::npos) {
            start += 3;
            size_t end = base_url.find('/', start);
            if (end != std::string::npos) {
                return base_url.substr(0, end) + specifier;
            }
        }
        // If base_url is esm.sh related, use esm.sh as host
        if (base_url.find("esm.sh") != std::string::npos) {
            return "https://esm.sh" + specifier;
        }
    }
    
    // Relative import starting with ./
    if (specifier.find("./") == 0) {
        return get_base_url(base_url) + specifier.substr(2);
    }
    
    // Relative import starting with ../
    if (specifier.find("../") == 0) {
        std::string base = get_base_url(base_url);
        std::string rel = specifier;
        
        while (rel.find("../") == 0) {
            rel = rel.substr(3);
            // Remove one directory from base
            if (base.size() > 8) {  // More than "https://"
                size_t pos = base.rfind('/', base.size() - 2);
                if (pos != std::string::npos && pos > 8) {
                    base = base.substr(0, pos + 1);
                }
            }
        }
        return base + rel;
    }
    
    // Bare specifier on esm.sh - resolve relative to esm.sh
    if (base_url.find("esm.sh") != std::string::npos || 
        base_url.find("https://esm.sh") != std::string::npos) {
        // For bare specifiers like "lodash", resolve to esm.sh
        if (!specifier.empty() && specifier[0] != '.' && specifier[0] != '/') {
            return "https://esm.sh/" + specifier;
        }
    }
    
    return specifier;
}

std::string ModuleResolver::url_to_var_name(const std::string& url) {
    std::string var = "__mod_";
    for (char c : url) {
        if (std::isalnum(static_cast<unsigned char>(c))) {
            var += c;
        } else {
            var += '_';
        }
    }
    return var;
}

std::vector<ImportInfo> ModuleResolver::parse_imports(std::string_view source) {
    return parse_imports_with_base(source, "");
}

std::vector<ImportInfo> ModuleResolver::parse_imports_with_base(std::string_view source, 
                                                                  const std::string& base_url) {
    std::vector<ImportInfo> imports;
    std::string src(source);
    std::sregex_iterator end;
    
    // Pattern 1: import defaultExport from "module"
    std::regex import_default_regex(
        R"(import\s+(\w+)\s+from\s+["']([^"']+)["'])",
        std::regex::ECMAScript
    );
    
    for (std::sregex_iterator it(src.begin(), src.end(), import_default_regex); it != end; ++it) {
        const std::smatch& match = *it;
        ImportInfo info;
        info.full_match = match[0].str();
        info.default_name = match[1].str();
        info.specifier = match[2].str();
        
        if (!base_url.empty() && !info.specifier.empty() && 
            (info.specifier[0] == '/' || info.specifier[0] == '.')) {
            info.specifier = normalize_url(base_url, info.specifier);
        }
        
        if (is_remote_url(info.specifier)) {
            imports.push_back(info);
        }
    }
    
    // Pattern 2: import { a, b as c } from "module"
    std::regex import_named_regex(
        R"(import\s+\{\s*([^}]+)\s*\}\s+from\s+["']([^"']+)["'])",
        std::regex::ECMAScript
    );
    
    for (std::sregex_iterator it(src.begin(), src.end(), import_named_regex); it != end; ++it) {
        const std::smatch& match = *it;
        ImportInfo info;
        info.full_match = match[0].str();
        info.specifier = match[2].str();
        
        // Parse named imports
        std::string named = match[1].str();
        std::regex name_regex(R"((\w+)(?:\s+as\s+(\w+))?)");
        for (std::sregex_iterator name_it(named.begin(), named.end(), name_regex); name_it != end; ++name_it) {
            info.names.push_back((*name_it)[0].str());
        }
        
        if (!base_url.empty() && !info.specifier.empty() && 
            (info.specifier[0] == '/' || info.specifier[0] == '.')) {
            info.specifier = normalize_url(base_url, info.specifier);
        }
        
        if (is_remote_url(info.specifier)) {
            imports.push_back(info);
        }
    }
    
    // Pattern 3: import * as name from "module"
    std::regex import_namespace_regex(
        R"(import\s+\*\s+as\s+(\w+)\s+from\s+["']([^"']+)["'])",
        std::regex::ECMAScript
    );
    
    for (std::sregex_iterator it(src.begin(), src.end(), import_namespace_regex); it != end; ++it) {
        const std::smatch& match = *it;
        ImportInfo info;
        info.full_match = match[0].str();
        info.namespace_name = match[1].str();
        info.specifier = match[2].str();
        
        if (!base_url.empty() && !info.specifier.empty() && 
            (info.specifier[0] == '/' || info.specifier[0] == '.')) {
            info.specifier = normalize_url(base_url, info.specifier);
        }
        
        if (is_remote_url(info.specifier)) {
            imports.push_back(info);
        }
    }
    
    // Pattern 4: import "module" (side-effect only)
    std::regex import_side_effect_regex(
        R"(import\s+["']([^"']+)["'])",
        std::regex::ECMAScript
    );
    
    for (std::sregex_iterator it(src.begin(), src.end(), import_side_effect_regex); it != end; ++it) {
        const std::smatch& match = *it;
        std::string specifier = match[1].str();
        
        // Skip if already matched by other patterns
        bool already_matched = false;
        for (const auto& existing : imports) {
            if (existing.specifier == specifier) {
                already_matched = true;
                break;
            }
        }
        if (already_matched) continue;
        
        ImportInfo info;
        info.full_match = match[0].str();
        info.specifier = specifier;
        
        if (!base_url.empty() && !info.specifier.empty() && 
            (info.specifier[0] == '/' || info.specifier[0] == '.')) {
            info.specifier = normalize_url(base_url, info.specifier);
        }
        
        if (is_remote_url(info.specifier)) {
            imports.push_back(info);
        }
    }
    
    // Pattern 5: export * from "module"
    std::regex export_star_regex(
        R"(export\s+\*\s+from\s+["']([^"']+)["'])",
        std::regex::ECMAScript
    );
    
    for (std::sregex_iterator it(src.begin(), src.end(), export_star_regex); it != end; ++it) {
        const std::smatch& match = *it;
        ImportInfo info;
        info.full_match = match[0].str();
        info.specifier = match[1].str();
        info.is_export_from = true;
        
        if (!base_url.empty() && !info.specifier.empty() && 
            (info.specifier[0] == '/' || info.specifier[0] == '.')) {
            info.specifier = normalize_url(base_url, info.specifier);
        }
        
        if (is_remote_url(info.specifier) || 
            (!base_url.empty() && !info.specifier.empty() && info.specifier[0] == '/')) {
            imports.push_back(info);
        }
    }
    
    // Pattern 6: export { a, b } from "module"
    std::regex export_named_regex(
        R"(export\s+\{\s*([^}]+)\s*\}\s+from\s+["']([^"']+)["'])",
        std::regex::ECMAScript
    );
    
    for (std::sregex_iterator it(src.begin(), src.end(), export_named_regex); it != end; ++it) {
        const std::smatch& match = *it;
        ImportInfo info;
        info.full_match = match[0].str();
        info.specifier = match[2].str();
        info.is_export_from = true;
        
        // Parse named exports
        std::string named = match[1].str();
        std::regex name_regex(R"((\w+)(?:\s+as\s+(\w+))?)");
        for (std::sregex_iterator name_it(named.begin(), named.end(), name_regex); name_it != end; ++name_it) {
            info.names.push_back((*name_it)[0].str());
        }
        
        if (!base_url.empty() && !info.specifier.empty() && 
            (info.specifier[0] == '/' || info.specifier[0] == '.')) {
            info.specifier = normalize_url(base_url, info.specifier);
        }
        
        if (is_remote_url(info.specifier) || 
            (!base_url.empty() && !info.specifier.empty() && info.specifier[0] == '/')) {
            imports.push_back(info);
        }
    }
    
    // Pattern 7: dynamic import("module")
    std::regex dynamic_regex(R"(import\s*\(\s*["']([^"']+)["']\s*\))");
    
    for (std::sregex_iterator it(src.begin(), src.end(), dynamic_regex); it != end; ++it) {
        const std::smatch& match = *it;
        ImportInfo info;
        info.full_match = match[0].str();
        info.specifier = match[1].str();
        info.is_dynamic = true;
        
        if (!base_url.empty() && !info.specifier.empty() && 
            (info.specifier[0] == '/' || info.specifier[0] == '.')) {
            info.specifier = normalize_url(base_url, info.specifier);
        }
        
        if (is_remote_url(info.specifier)) {
            imports.push_back(info);
        }
    }
    
    return imports;
}

std::string ModuleResolver::fetch_module(const std::string& url) {
    // Check cache first
    auto it = module_cache_.find(url);
    if (it != module_cache_.end()) {
        return it->second;
    }
    
    std::string normalized_url = url;
    if (url.find("esm.sh/") == 0) {
        normalized_url = "https://" + url;
    }
    
    CURL* curl = curl_easy_init();
    if (!curl) {
        throw std::runtime_error("Failed to initialize CURL");
    }
    
    std::string response_body;
    struct curl_slist* headers = nullptr;
    
    // Set user agent to get ESM format
    headers = curl_slist_append(headers, "User-Agent: quickwork/1.0");
    
    curl_easy_setopt(curl, CURLOPT_URL, normalized_url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_body);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    
    CURLcode res = curl_easy_perform(curl);
    
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    
    // Get final URL after redirects
    char* final_url = nullptr;
    curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &final_url);
    std::string effective_url = final_url ? final_url : normalized_url;
    
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    
    if (res != CURLE_OK) {
        throw std::runtime_error("Failed to fetch module " + url + ": " + 
                                curl_easy_strerror(res));
    }
    
    if (http_code != 200) {
        throw std::runtime_error("HTTP error " + std::to_string(http_code) + 
                                " fetching module: " + url);
    }
    
    // Cache with both original and effective URL
    module_cache_[url] = response_body;
    if (effective_url != url && effective_url != normalized_url) {
        module_cache_[effective_url] = response_body;
    }
    
    return response_body;
}

std::string ModuleResolver::resolve_module(const std::string& url,
                                            std::unordered_set<std::string>& visited) {
    std::string normalized_url = url;
    if (url.find("esm.sh/") == 0) {
        normalized_url = "https://" + url;
    }
    
    // Avoid circular imports
    if (visited.count(normalized_url)) {
        return "";
    }
    visited.insert(normalized_url);
    
    std::string source = fetch_module(normalized_url);
    
    // Parse and resolve nested imports (with base URL for relative paths)
    auto imports = parse_imports_with_base(source, normalized_url);
    
    std::ostringstream bundled;
    
    // First, recursively resolve all dependencies
    for (const auto& imp : imports) {
        std::string dep_url = normalize_url(normalized_url, imp.specifier);
        std::string dep_source = resolve_module(dep_url, visited);
        if (!dep_source.empty()) {
            bundled << dep_source << "\n";
        }
    }
    
    // Transform this module's imports to use our bundled modules
    std::string transformed = source;
    
    for (const auto& imp : imports) {
        std::string dep_url = imp.specifier;  // Already normalized by parse_imports_with_base
        std::string var_name = url_to_var_name(dep_url);
        
        if (imp.is_dynamic) {
            // Replace dynamic import with reference to bundled module
            std::string replacement = "Promise.resolve(" + var_name + ")";
            size_t pos = transformed.find(imp.full_match);
            if (pos != std::string::npos) {
                transformed.replace(pos, imp.full_match.length(), replacement);
            }
        } else if (imp.is_export_from) {
            // Handle: export * from "module" -> copy all exports from dep module
            // Handle: export { a, b } from "module" -> copy specific exports
            size_t pos = transformed.find(imp.full_match);
            if (pos != std::string::npos) {
                std::ostringstream re_export;
                if (imp.full_match.find("*") != std::string::npos) {
                    // export * from - re-export all
                    re_export << "Object.assign(__exports, " << var_name << ");\n";
                } else {
                    // export { a, b } from - re-export specific
                    for (const auto& named : imp.names) {
                        size_t as_pos = named.find(" as ");
                        if (as_pos != std::string::npos) {
                            std::string orig = named.substr(0, as_pos);
                            std::string alias = named.substr(as_pos + 4);
                            orig.erase(0, orig.find_first_not_of(" \t"));
                            orig.erase(orig.find_last_not_of(" \t") + 1);
                            alias.erase(0, alias.find_first_not_of(" \t"));
                            alias.erase(alias.find_last_not_of(" \t") + 1);
                            re_export << "__exports." << alias << " = " << var_name << "." << orig << ";\n";
                        } else {
                            std::string name = named;
                            name.erase(0, name.find_first_not_of(" \t"));
                            name.erase(name.find_last_not_of(" \t") + 1);
                            if (!name.empty()) {
                                re_export << "__exports." << name << " = " << var_name << "." << name << ";\n";
                            }
                        }
                    }
                }
                transformed.replace(pos, imp.full_match.length(), re_export.str());
            }
        } else {
            // Remove static import statement (module is already bundled above)
            size_t pos = transformed.find(imp.full_match);
            if (pos != std::string::npos) {
                // Generate variable assignments for the imports
                std::ostringstream assignments;
                
                if (!imp.default_name.empty()) {
                    assignments << "const " << imp.default_name << " = " 
                               << var_name << ".default || " << var_name << ";\n";
                }
                
                if (!imp.namespace_name.empty()) {
                    assignments << "const " << imp.namespace_name << " = " << var_name << ";\n";
                }
                
                for (const auto& named : imp.names) {
                    // Handle "x as y" syntax
                    size_t as_pos = named.find(" as ");
                    if (as_pos != std::string::npos) {
                        std::string orig = named.substr(0, as_pos);
                        std::string alias = named.substr(as_pos + 4);
                        // Trim whitespace
                        orig.erase(0, orig.find_first_not_of(" \t"));
                        orig.erase(orig.find_last_not_of(" \t") + 1);
                        alias.erase(0, alias.find_first_not_of(" \t"));
                        alias.erase(alias.find_last_not_of(" \t") + 1);
                        assignments << "const " << alias << " = " << var_name << "." << orig << ";\n";
                    } else {
                        std::string name = named;
                        name.erase(0, name.find_first_not_of(" \t"));
                        name.erase(name.find_last_not_of(" \t") + 1);
                        assignments << "const " << name << " = " << var_name << "." << name << ";\n";
                    }
                }
                
                transformed.replace(pos, imp.full_match.length(), assignments.str());
            }
        }
    }
    
    // Wrap module in IIFE and export to module variable
    std::string var_name = url_to_var_name(normalized_url);
    
    // Transform export statements to collect exports
    std::ostringstream module_wrapper;
    module_wrapper << "const " << var_name << " = (function() {\n";
    module_wrapper << "  const __exports = {};\n";
    
    // Transform: export default X -> __exports.default = X
    // Transform: export { a, b } -> __exports.a = a; __exports.b = b;
    // Transform: export const/let/var X = ... -> const X = ...; __exports.X = X;
    
    std::string with_exports = transformed;
    
    // Handle "export default"
    std::regex export_default_regex(R"(export\s+default\s+)");
    with_exports = std::regex_replace(with_exports, export_default_regex, "__exports.default = ");
    
    // Handle "export { ... }"
    std::regex export_named_regex(R"(export\s*\{([^}]+)\})");
    std::smatch named_match;
    std::string temp = with_exports;
    while (std::regex_search(temp, named_match, export_named_regex)) {
        std::string names_str = named_match[1].str();
        std::ostringstream export_assigns;
        
        std::regex name_regex(R"((\w+)(?:\s+as\s+(\w+))?)");
        std::sregex_iterator name_it(names_str.begin(), names_str.end(), name_regex);
        std::sregex_iterator name_end;
        
        for (; name_it != name_end; ++name_it) {
            std::string local_name = (*name_it)[1].str();
            std::string export_name = (*name_it)[2].matched ? (*name_it)[2].str() : local_name;
            export_assigns << "__exports." << export_name << " = " << local_name << "; ";
        }
        
        size_t pos = with_exports.find(named_match[0].str());
        if (pos != std::string::npos) {
            with_exports.replace(pos, named_match[0].str().length(), export_assigns.str());
        }
        temp = named_match.suffix().str();
    }
    
    // Handle "export const/let/var X = ..."
    std::regex export_decl_regex(R"(export\s+(const|let|var)\s+(\w+)\s*=)");
    temp = with_exports;
    while (std::regex_search(temp, named_match, export_decl_regex)) {
        std::string decl_type = named_match[1].str();
        std::string var_name_export = named_match[2].str();
        
        std::string replacement = decl_type + " " + var_name_export + " = __exports." + 
                                  var_name_export + " = ";
        
        size_t pos = with_exports.find(named_match[0].str());
        if (pos != std::string::npos) {
            with_exports.replace(pos, named_match[0].str().length(), replacement);
        }
        temp = named_match.suffix().str();
    }
    
    // Handle "export function X" and "export class X"
    std::regex export_func_regex(R"(export\s+(function|class)\s+(\w+))");
    temp = with_exports;
    while (std::regex_search(temp, named_match, export_func_regex)) {
        std::string type = named_match[1].str();
        std::string name = named_match[2].str();
        
        // Keep the function/class declaration, add export assignment after
        std::string replacement = type + " " + name;
        
        size_t pos = with_exports.find(named_match[0].str());
        if (pos != std::string::npos) {
            with_exports.replace(pos, named_match[0].str().length(), replacement);
            // We'll need to add __exports.name = name after the declaration
            // For simplicity, we'll add it at the end of the module
        }
        temp = named_match.suffix().str();
    }
    
    module_wrapper << with_exports << "\n";
    module_wrapper << "  return __exports;\n";
    module_wrapper << "})();\n";
    
    bundled << module_wrapper.str();
    
    return bundled.str();
}

// Check if a specifier is a built-in module
bool ModuleResolver::is_builtin_module(const std::string& specifier) {
    return specifier == "quickw";
}

// Get polyfill imports to prepend to user code
std::string ModuleResolver::get_polyfill_imports() {
    // Import polyfills from esm.sh for APIs not natively available in QuickJS
    // These are side-effect imports that patch the global object
    return R"(
import "https://esm.sh/core-js/actual/url";
import "https://esm.sh/core-js/actual/url-search-params";
import "https://esm.sh/core-js/actual/structured-clone";
import "https://esm.sh/core-js/actual/atob";
import "https://esm.sh/core-js/actual/btoa";
import "https://esm.sh/core-js/actual/queue-microtask";
import "https://esm.sh/core-js/actual/set";
)";}


// Transform built-in module imports to use the global module initializer
std::string ModuleResolver::transform_builtin_import(const ImportInfo& imp) {
    std::ostringstream code;
    
    if (imp.specifier == "quickw") {
        // Call the built-in module initializer
        code << "const __quickw_mod__ = __quickw_kv_module__();\n";
        
        if (!imp.default_name.empty()) {
            code << "const " << imp.default_name << " = __quickw_mod__;\n";
        }
        
        if (!imp.namespace_name.empty()) {
            code << "const " << imp.namespace_name << " = __quickw_mod__;\n";
        }
        
        for (const auto& named : imp.names) {
            size_t as_pos = named.find(" as ");
            if (as_pos != std::string::npos) {
                std::string orig = named.substr(0, as_pos);
                std::string alias = named.substr(as_pos + 4);
                orig.erase(0, orig.find_first_not_of(" \t"));
                orig.erase(orig.find_last_not_of(" \t") + 1);
                alias.erase(0, alias.find_first_not_of(" \t"));
                alias.erase(alias.find_last_not_of(" \t") + 1);
                code << "const " << alias << " = __quickw_mod__." << orig << ";\n";
            } else {
                std::string name = named;
                name.erase(0, name.find_first_not_of(" \t"));
                name.erase(name.find_last_not_of(" \t") + 1);
                if (!name.empty()) {
                    code << "const " << name << " = __quickw_mod__." << name << ";\n";
                }
            }
        }
    }
    
    return code.str();
}

std::string ModuleResolver::resolve_and_bundle(std::string_view source) {
    // Prepend polyfill imports to the source
    std::string src = get_polyfill_imports() + std::string(source);
    
    // Parse imports from the source (including polyfills)
    auto imports = parse_imports(src);
    
    // Also parse built-in module imports (they won't be caught by is_remote_url)
    std::vector<ImportInfo> builtin_imports;
    
    // Parse all imports including built-ins
    std::regex import_default_regex(
        R"(import\s+(\w+)\s+from\s+["']([^"']+)["'])",
        std::regex::ECMAScript
    );
    std::regex import_named_regex(
        R"(import\s+\{\s*([^}]+)\s*\}\s+from\s+["']([^"']+)["'])",
        std::regex::ECMAScript
    );
    std::regex import_namespace_regex(
        R"(import\s+\*\s+as\s+(\w+)\s+from\s+["']([^"']+)["'])",
        std::regex::ECMAScript
    );
    
    std::sregex_iterator end;
    
    // Check for builtin imports - default
    for (std::sregex_iterator it(src.begin(), src.end(), import_default_regex); it != end; ++it) {
        const std::smatch& match = *it;
        std::string specifier = match[2].str();
        if (is_builtin_module(specifier)) {
            ImportInfo info;
            info.full_match = match[0].str();
            info.default_name = match[1].str();
            info.specifier = specifier;
            builtin_imports.push_back(info);
        }
    }
    
    // Check for builtin imports - named
    for (std::sregex_iterator it(src.begin(), src.end(), import_named_regex); it != end; ++it) {
        const std::smatch& match = *it;
        std::string specifier = match[2].str();
        if (is_builtin_module(specifier)) {
            ImportInfo info;
            info.full_match = match[0].str();
            info.specifier = specifier;
            
            std::string named = match[1].str();
            std::regex name_regex(R"((\w+)(?:\s+as\s+(\w+))?)");
            for (std::sregex_iterator name_it(named.begin(), named.end(), name_regex); name_it != end; ++name_it) {
                info.names.push_back((*name_it)[0].str());
            }
            builtin_imports.push_back(info);
        }
    }
    
    // Check for builtin imports - namespace
    for (std::sregex_iterator it(src.begin(), src.end(), import_namespace_regex); it != end; ++it) {
        const std::smatch& match = *it;
        std::string specifier = match[2].str();
        if (is_builtin_module(specifier)) {
            ImportInfo info;
            info.full_match = match[0].str();
            info.namespace_name = match[1].str();
            info.specifier = specifier;
            builtin_imports.push_back(info);
        }
    }
    
    // Transform built-in imports first
    std::string transformed = src;
    for (const auto& imp : builtin_imports) {
        size_t pos = transformed.find(imp.full_match);
        if (pos != std::string::npos) {
            std::string replacement = transform_builtin_import(imp);
            transformed.replace(pos, imp.full_match.length(), replacement);
        }
    }
    
    if (imports.empty()) {
        // No remote imports, return transformed source (may have built-in imports)
        return transformed;
    }
    
    std::unordered_set<std::string> visited;
    std::ostringstream bundled;
    
    // Add a header comment
    bundled << "/* Bundled by quickwork module resolver */\n\n";
    
    // Resolve and bundle each remote import
    for (const auto& imp : imports) {
        std::string url = imp.specifier;
        if (url.find("esm.sh/") == 0) {
            url = "https://" + url;
        }
        
        std::string module_source = resolve_module(url, visited);
        if (!module_source.empty()) {
            bundled << module_source << "\n";
        }
    }
    
    // Transform the source to use bundled modules (for remote imports)
    for (const auto& imp : imports) {
        std::string url = imp.specifier;
        if (url.find("esm.sh/") == 0) {
            url = "https://" + url;
        }
        std::string var_name = url_to_var_name(url);
        
        if (imp.is_dynamic) {
            // Replace dynamic import with reference to bundled module
            std::string replacement = "Promise.resolve(" + var_name + ")";
            size_t pos = transformed.find(imp.full_match);
            if (pos != std::string::npos) {
                transformed.replace(pos, imp.full_match.length(), replacement);
            }
        } else {
            size_t pos = transformed.find(imp.full_match);
            if (pos != std::string::npos) {
                std::ostringstream assignments;
                
                if (!imp.default_name.empty()) {
                    assignments << "const " << imp.default_name << " = " 
                               << var_name << ".default || " << var_name << ";\n";
                }
                
                if (!imp.namespace_name.empty()) {
                    assignments << "const " << imp.namespace_name << " = " << var_name << ";\n";
                }
                
                for (const auto& named : imp.names) {
                    size_t as_pos = named.find(" as ");
                    if (as_pos != std::string::npos) {
                        std::string orig = named.substr(0, as_pos);
                        std::string alias = named.substr(as_pos + 4);
                        orig.erase(0, orig.find_first_not_of(" \t"));
                        orig.erase(orig.find_last_not_of(" \t") + 1);
                        alias.erase(0, alias.find_first_not_of(" \t"));
                        alias.erase(alias.find_last_not_of(" \t") + 1);
                        assignments << "const " << alias << " = " << var_name << "." << orig << ";\n";
                    } else {
                        std::string name = named;
                        name.erase(0, name.find_first_not_of(" \t"));
                        name.erase(name.find_last_not_of(" \t") + 1);
                        if (!name.empty()) {
                            assignments << "const " << name << " = " << var_name << "." << name << ";\n";
                        }
                    }
                }
                
                // If no specific imports, might be a side-effect import
                if (imp.default_name.empty() && imp.namespace_name.empty() && imp.names.empty()) {
                    assignments << "/* side-effect import: " << imp.specifier << " */\n";
                }
                
                transformed.replace(pos, imp.full_match.length(), assignments.str());
            }
        }
    }
    
    bundled << "\n/* Main handler */\n";
    bundled << transformed;
    
    return bundled.str();
}

}  // namespace quickwork
