#include "config.hpp"
#include "server.hpp"

#include <boost/program_options.hpp>
#include <curl/curl.h>

#include <csignal>
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
}  // namespace

int main(int argc, char* argv[]) {
    quickwork::Config config;

    po::options_description desc("QuickWork - Multithreaded QuickJS Web Server");
    desc.add_options()
        ("help,h", "Show help message")
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
        std::cout << "  # Start the server\n";
        std::cout << "  ./quickwork -p 8080\n\n";
        std::cout << "  # Register a handler (POST without x-handler-id)\n";
        std::cout << R"(  curl -X POST http://localhost:8080 -d 'export default (req) => new Response("Hello!")')" << "\n\n";
        std::cout << "  # Execute a handler (any method with x-handler-id)\n";
        std::cout << "  curl http://localhost:8080 -H 'x-handler-id: <id>'\n";
        return 0;
    }

    if (vm.count("cache-dir")) {
        config.cache_dir = vm["cache-dir"].as<std::string>();
    }

    // Set up signal handlers
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    // Initialize libcurl globally (required for thread safety)
    curl_global_init(CURL_GLOBAL_ALL);

    std::cout << "QuickWork v1.0.0\n";
    std::cout << "===============\n";
    std::cout << "Cache directory: " << config.cache_dir << "\n";
    std::cout << "Handler cache: " << config.handler_cache_size << " entries\n";
    std::cout << "Max memory: " << config.max_memory_mb << " MB\n";
    std::cout << "Max CPU time: " << config.max_cpu_time_ms << " ms\n";
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
