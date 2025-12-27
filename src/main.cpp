#include "config.hpp"
#include "kv_store.hpp"
#include "server.hpp"

#include <boost/program_options.hpp>
#include <curl/curl.h>

#include <csignal>
#include <fstream>
#include <iostream>
#include <memory>

namespace po = boost::program_options;

namespace {
std::unique_ptr<quickwork::Server> g_server;

void signal_handler(int /*signum*/) {
    if (g_server) {
        std::cout << "\nShutting down...\n";
        g_server->stop();
    }
    std::exit(0);
}

// Add .qw to .gitignore if it exists and doesn't already contain .qw
void ensure_gitignore_entry() {
    std::filesystem::path gitignore_path = ".gitignore";
    
    if (!std::filesystem::exists(gitignore_path)) {
        return;  // No .gitignore, nothing to do
    }
    
    // Read existing content
    std::ifstream in(gitignore_path);
    if (!in) {
        return;
    }
    
    std::string content;
    std::string line;
    bool has_qw_entry = false;
    
    while (std::getline(in, line)) {
        content += line + "\n";
        // Check if .qw is already in gitignore (with or without trailing slash)
        if (line == ".qw" || line == ".qw/" || line == "/.qw" || line == "/.qw/") {
            has_qw_entry = true;
        }
    }
    in.close();
    
    if (has_qw_entry) {
        return;  // Already present
    }
    
    // Append .qw to gitignore
    std::ofstream out(gitignore_path, std::ios::app);
    if (!out) {
        std::cerr << "Warning: Could not update .gitignore\n";
        return;
    }
    
    // Add newline if file doesn't end with one
    if (!content.empty() && content.back() != '\n') {
        out << "\n";
    }
    out << ".qw/\n";
    out.close();
    
    std::cout << "Added .qw/ to .gitignore\n";
}

// Initialize project for QuickWork dev mode with TypeScript/TSX support
int run_init() {
    namespace fs = std::filesystem;
    
    std::cout << "Initializing QuickWork project...\n\n";
    
    // Create tsconfig.json for TypeScript support
    fs::path tsconfig_path = "tsconfig.json";
    if (!fs::exists(tsconfig_path)) {
        std::ofstream tsconfig(tsconfig_path);
        if (tsconfig) {
            tsconfig << R"({
  "compilerOptions": {
    "target": "ES2020",
    "module": "ESNext",
    "moduleResolution": "bundler",
    "jsx": "react-jsx",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "outDir": ".qw/dist",
    "declaration": false,
    "noEmit": true
  },
  "include": ["*.ts", "*.tsx", "src/**/*.ts", "src/**/*.tsx"],
  "exclude": ["node_modules", ".qw"]
}
)";
            tsconfig.close();
            std::cout << "Created tsconfig.json\n";
        } else {
            std::cerr << "Warning: Could not create tsconfig.json\n";
        }
    } else {
        std::cout << "tsconfig.json already exists, skipping\n";
    }
    
    // Create .gitignore if it doesn't exist
    fs::path gitignore_path = ".gitignore";
    bool gitignore_existed = fs::exists(gitignore_path);
    if (!gitignore_existed) {
        std::ofstream gitignore(gitignore_path);
        if (gitignore) {
            gitignore << "node_modules/\n.qw/\n";
            gitignore.close();
            std::cout << "Created .gitignore\n";
        }
    } else {
        ensure_gitignore_entry();
    }
    
    // Create a sample handler if no .ts/.tsx/.js files exist
    bool has_handler = false;
    for (const auto& entry : fs::directory_iterator(".")) {
        if (entry.is_regular_file()) {
            std::string ext = entry.path().extension().string();
            if (ext == ".ts" || ext == ".tsx" || ext == ".js" || ext == ".jsx") {
                has_handler = true;
                break;
            }
        }
    }
    
    if (!has_handler) {
        fs::path handler_path = "index.tsx";
        std::ofstream handler(handler_path);
        if (handler) {
            handler << R"(// QuickWork handler with React JSX support
// Run with: quickw --dev index.tsx

interface Request {
  method: string;
  url: string;
  headers: Record<string, string>;
  body: string;
}

export default function handler(req: Request): Response {
  const name = new URL(req.url, "http://localhost").searchParams.get("name") || "World";
  
  return new Response(
    `<!DOCTYPE html>
<html>
<head><title>QuickWork</title></head>
<body>
  <h1>Hello, ${name}!</h1>
  <p>Method: ${req.method}</p>
</body>
</html>`,
    {
      headers: { "Content-Type": "text/html" }
    }
  );
}
)";
            handler.close();
            std::cout << "Created index.tsx (sample handler)\n";
        }
    }
    
    // Check for package.json and suggest installing esbuild
    fs::path package_json = "package.json";
    if (!fs::exists(package_json)) {
        std::cout << "\nTo complete setup, run:\n";
        std::cout << "  npm init -y\n";
        std::cout << "  npm install -D esbuild typescript @types/react\n";
    } else {
        // Check if esbuild is installed
        fs::path esbuild_bin = "node_modules/.bin/esbuild";
        if (!fs::exists(esbuild_bin)) {
            std::cout << "\nTo complete setup, run:\n";
            std::cout << "  npm install -D esbuild typescript @types/react\n";
        }
    }
    
    std::cout << "\nQuickWork project initialized!\n";
    std::cout << "Run with: quickw --dev index.tsx\n";
    
    return 0;
}
}  // namespace

int main(int argc, char* argv[]) {
    quickwork::Config config;
    std::string dev_file;

    po::options_description desc("QuickWork - Multithreaded QuickJS Web Server");
    desc.add_options()
        ("help,h", "Show help message")
        ("init", "Initialize project for QuickWork dev mode (creates tsconfig.json, etc.)")
        ("dev,d", po::value<std::string>(&dev_file),
            "Dev mode: watch handler file and auto-reload on changes (supports .ts, .tsx, .jsx)")
        ("host,H", po::value<std::string>(&config.host)->default_value("0.0.0.0"),
            "Host to bind to")
        ("port,p", po::value<uint16_t>(&config.port)->default_value(8080),
            "Port to listen on")
        ("cache-dir,c", po::value<std::string>()->default_value("./handlers"),
            "Handler cache directory")
        ("max-memory,m", po::value<size_t>(&config.max_memory_mb)->default_value(64),
            "Max memory per runtime in MB")
        ("max-cpu-time,t", po::value<uint32_t>(&config.max_cpu_time_ms)->default_value(5000),
            "Max CPU time per request in ms")
        ("threads,j", po::value<size_t>(&config.thread_count)->default_value(0),
            "Number of worker threads (0 = auto)")
        ("cache-size,s", po::value<size_t>(&config.handler_cache_size)->default_value(1024),
            "Max handlers in memory cache (LRU)")
        ("max-storage,S", po::value<size_t>(&config.max_cache_storage_mb)->default_value(0),
            "Max disk storage for bytecode cache in MB (0 = unlimited)")
        ("kv-size,k", po::value<size_t>(&config.kv_max_entries)->default_value(10 * 1024),
            "Max entries in shared KV store (LRU eviction)")
    ;

    po::variables_map vm;
    try {
        po::store(po::parse_command_line(argc, argv, desc), vm);
        po::notify(vm);
    } catch (const po::error& e) {
        std::cerr << "Error: " << e.what() << "\n";
        std::cerr << desc << "\n";
        return 1;
    }

    if (vm.count("help")) {
        std::cout << desc << "\n";
        std::cout << "\nUsage:\n";
        std::cout << "  # Initialize a new project\n";
        std::cout << "  quickw --init\n\n";
        std::cout << "  # Dev mode with auto-reload (TypeScript/TSX/JSX supported)\n";
        std::cout << "  quickw --dev handler.tsx\n\n";
        std::cout << "  # Start the production server\n";
        std::cout << "  quickw -p 8080\n\n";
        std::cout << "  # Register a handler (POST without x-handler-id)\n";
        std::cout << R"(  curl -X POST http://localhost:8080 -d 'export default (req) => new Response("Hello!")')" << "\n\n";
        std::cout << "  # Execute a handler (any method with x-handler-id)\n";
        std::cout << "  curl http://localhost:8080 -H 'x-handler-id: <id>'\n";
        return 0;
    }

    // Handle init command
    if (vm.count("init")) {
        return run_init();
    }

    // Handle dev mode
    if (vm.count("dev")) {
        config.dev_mode = true;
        config.dev_handler_file = dev_file;
        config.cache_dir = "./.qw/handlers";
        
        // Verify handler file exists
        if (!std::filesystem::exists(config.dev_handler_file)) {
            std::cerr << "Error: Handler file not found: " << config.dev_handler_file << "\n";
            return 1;
        }
        
        // Add .qw to .gitignore if applicable
        ensure_gitignore_entry();
    }

    if (vm.count("cache-dir") && !config.dev_mode) {
        config.cache_dir = vm["cache-dir"].as<std::string>();
    }

    // Set up signal handlers
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    // Initialize libcurl globally (required for thread safety)
    curl_global_init(CURL_GLOBAL_ALL);

    // Initialize the global KV store
    quickwork::KvStore::init(config.kv_max_entries);

    std::cout << "QuickWork v1.0.0\n";
    std::cout << "===============\n";
    if (config.dev_mode) {
        std::cout << "Mode: DEV (auto-reload enabled)\n";
        std::cout << "Handler: " << config.dev_handler_file << "\n";
    }
    std::cout << "Cache directory: " << config.cache_dir << "\n";
    std::cout << "Handler cache: " << config.handler_cache_size << " entries\n";
    std::cout << "Max storage: " << (config.max_cache_storage_mb == 0 ? "unlimited" : std::to_string(config.max_cache_storage_mb) + " MB") << "\n";
    std::cout << "Max memory: " << config.max_memory_mb << " MB\n";
    std::cout << "Max CPU time: " << config.max_cpu_time_ms << " ms\n";
    std::cout << "KV store: " << config.kv_max_entries << " max entries\n";
    std::cout << "Threads: " << (config.thread_count == 0 ? std::thread::hardware_concurrency() : config.thread_count) << "\n\n";

    try {
        g_server = std::make_unique<quickwork::Server>(config);
        g_server->run();
    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << "\n";
        curl_global_cleanup();
        return 1;
    }

    curl_global_cleanup();
    return 0;
}
