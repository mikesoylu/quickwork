#include "server.hpp"
#include "js_runtime.hpp"
#include "js_bindings.hpp"

#include <boost/asio.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <csignal>
#include <sstream>

namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
using tcp = net::ip::tcp;

namespace quickwork {

namespace {

// Extract handler ID from subdomain in Host header
// Format: <handler-id>.<base-domain> -> handler-id
// Returns empty string if no valid subdomain found
std::string extract_handler_id_from_host(std::string_view host) {
    // Remove port if present
    auto port_pos = host.find(':');
    if (port_pos != std::string_view::npos) {
        host = host.substr(0, port_pos);
    }
    
    if (host.empty()) {
        return "";
    }
    
    // Skip IP addresses (no subdomain support for IPs)
    // Check for IPv4: all characters are digits or dots
    bool is_ipv4 = std::all_of(host.begin(), host.end(), [](char c) {
        return std::isdigit(static_cast<unsigned char>(c)) || c == '.';
    });
    if (is_ipv4) {
        return "";
    }
    
    // Find first dot - everything before it is the subdomain (handler ID)
    auto dot_pos = host.find('.');
    if (dot_pos == std::string_view::npos || dot_pos == 0) {
        return "";  // No subdomain or empty subdomain
    }
    
    // The subdomain is the handler ID
    return std::string(host.substr(0, dot_pos));
}

class Session : public std::enable_shared_from_this<Session> {
public:
    Session(tcp::socket socket, Server& server, HandlerStore& store, ThreadPool& pool)
        : stream_(std::move(socket))
        , server_(server)
        , handler_store_(store)
        , thread_pool_(pool)
    {
    }

    ~Session() {
        // Ensure request is marked as finished if it was started
        if (request_active_) {
            server_.request_finished();
        }
    }

    void run() {
        do_read();
    }

private:
    void do_read() {
        request_ = {};

        stream_.expires_after(std::chrono::seconds(30));

        http::async_read(stream_, buffer_, request_,
            beast::bind_front_handler(&Session::on_read, shared_from_this()));
    }

    void on_read(beast::error_code ec, std::size_t /*bytes_transferred*/) {
        if (ec == http::error::end_of_stream) {
            return do_close();
        }

        if (ec) {
            std::cerr << "Read error: " << ec.message() << "\n";
            return;
        }

        handle_request();
    }

    void handle_request() {
        // Health check endpoint
        if (request_.method() == http::verb::get && request_.target() == "/health") {
            http::response<http::string_body> res{http::status::ok, request_.version()};
            res.set(http::field::server, "quickwork");
            res.set(http::field::content_type, "application/json");
            res.keep_alive(request_.keep_alive());
            res.body() = R"({"status":"ok"})";
            res.prepare_payload();
            send_response(std::move(res));
            return;
        }

        // Check for handler-id header
        auto handler_id_it = request_.find("x-handler-id");
        
        // Try to get handler ID from subdomain if header not present
        std::string handler_id;
        if (handler_id_it != request_.end()) {
            handler_id = std::string(handler_id_it->value());
        } else {
            // Try extracting from Host header subdomain
            auto host_it = request_.find(http::field::host);
            if (host_it != request_.end()) {
                handler_id = extract_handler_id_from_host(host_it->value());
            }
        }

        if (request_.method() == http::verb::post && handler_id.empty()) {
            // Handler loader endpoint (disabled in dev mode)
            if (server_.is_dev_mode()) {
                send_error(400, "Handler registration disabled in dev mode");
                return;
            }
            handle_loader();
        } else if (!handler_id.empty()) {
            // Execute handler by ID (from header or subdomain)
            handle_execute(handler_id);
        } else if (server_.is_dev_mode()) {
            // Dev mode: use the dev handler for all requests without x-handler-id
            std::string dev_id = server_.get_dev_handler_id();
            if (dev_id.empty()) {
                send_error(500, "Dev handler not loaded");
                return;
            }
            handle_execute(dev_id);
        } else {
            // No handler specified
            send_error(400, "Missing x-handler-id header or subdomain");
        }
    }

    void handle_loader() {
        // Check deploy token if required
        if (server_.requires_deploy_token()) {
            auto token_it = request_.find("x-deploy-token");
            std::string_view token = token_it != request_.end() ? token_it->value() : "";
            if (!server_.check_deploy_token(token)) {
                send_error(401, "Invalid or missing deploy token");
                return;
            }
        }

        // Track active request for idle timeout
        if (!request_active_) {
            request_active_ = true;
            server_.request_started();
        }

        try {
            std::string source = request_.body();
            if (source.empty()) {
                send_error(400, "Empty handler source");
                return;
            }

            std::string id = server_.store_handler(source);

            http::response<http::string_body> res{http::status::ok, request_.version()};
            res.set(http::field::server, "quickwork");
            res.set(http::field::content_type, "application/json");
            res.keep_alive(request_.keep_alive());
            res.body() = R"({"id":")" + id + R"("})";
            res.prepare_payload();

            send_response(std::move(res));
        } catch (const std::exception& e) {
            send_error(500, e.what());
        }
    }

    void handle_execute(const std::string& handler_id) {
        auto bytecode_opt = handler_store_.load(handler_id);
        if (!bytecode_opt) {
            send_error(404, "Handler not found", true);
            return;
        }

        // Track active request for idle timeout
        if (!request_active_) {
            request_active_ = true;
            server_.request_started();
        }

        // Build request object for JS
        HttpRequest js_request;
        js_request.method = std::string(request_.method_string());
        js_request.url = std::string(request_.target());
        js_request.body = request_.body();

        for (const auto& field : request_) {
            js_request.headers[std::string(field.name_string())] =
                std::string(field.value());
        }

        Bytecode bytecode = std::move(*bytecode_opt);

        // Execute on thread pool - uses async handler API that allows concurrent requests per thread
        auto self = shared_from_this();
        
        // Shared state for streaming
        auto streaming_state = std::make_shared<StreamingState>();
        
        // Create stream writer that queues chunks for async delivery
        StreamWriter stream_writer = [self, streaming_state](std::string_view chunk) {
            std::lock_guard<std::mutex> lock(streaming_state->mutex);
            streaming_state->chunks.push(std::string(chunk));
            streaming_state->has_data = true;
            streaming_state->cv.notify_one();
        };
        
        thread_pool_.enqueue_handler(
            std::move(bytecode),
            std::move(js_request),
            [self, streaming_state](ExecutionResult result) {
                // Signal streaming complete
                {
                    std::lock_guard<std::mutex> lock(streaming_state->mutex);
                    streaming_state->complete = true;
                    streaming_state->cv.notify_one();
                }
                
                // Post the response back to the session's executor
                net::post(self->stream_.get_executor(), [self, streaming_state, result = std::move(result)]() {
                    // Check if this was a streaming response (with lock for thread safety)
                    {
                        std::lock_guard<std::mutex> lock(streaming_state->mutex);
                        if (streaming_state->has_data) {
                            // Streaming was handled separately
                            return;
                        }
                    }
                    
                    if (result.response) {
                        self->send_js_response(*result.response, result.stats);
                    } else {
                        self->send_error(500, result.error.empty() ? "Handler execution failed" : result.error);
                    }
                });
            },
            std::move(stream_writer)
        );
        
        // Start streaming consumer on this thread
        // This will send chunks as they become available
        net::post(stream_.get_executor(), [self, streaming_state]() {
            self->consume_stream(streaming_state);
        });
    }
    
    struct StreamingState {
        std::mutex mutex;
        std::condition_variable cv;
        std::queue<std::string> chunks;
        bool headers_sent = false;
        bool complete = false;
        bool has_data = false;
        bool consumer_active = false;  // Prevent multiple consumers
    };
    
    // Non-blocking stream consumer - processes available chunks and reschedules itself
    void consume_stream(std::shared_ptr<StreamingState> state) {
        std::vector<std::string> chunks_to_send;
        bool should_finish = false;
        bool should_reschedule = false;
        bool need_headers = false;
        
        // Quick lock to check state and grab any available chunks
        {
            std::lock_guard<std::mutex> lock(state->mutex);
            
            // If already complete with no data, let regular callback handle it
            if (state->complete && !state->has_data) {
                return;
            }
            
            // If no data yet and not complete, reschedule
            if (!state->has_data && !state->complete) {
                should_reschedule = true;
            } else if (state->has_data) {
                // Check if we need to send headers
                if (!state->headers_sent) {
                    state->headers_sent = true;
                    need_headers = true;
                }
                
                // Grab all available chunks
                while (!state->chunks.empty()) {
                    chunks_to_send.push_back(std::move(state->chunks.front()));
                    state->chunks.pop();
                }
                
                // Check if we're done
                if (state->complete && state->chunks.empty()) {
                    should_finish = true;
                } else {
                    should_reschedule = true;
                }
            }
        }
        
        // Reschedule if we need to wait for more data
        if (should_reschedule && chunks_to_send.empty() && !should_finish) {
            auto self = shared_from_this();
            // Use a timer for a short delay to avoid busy spinning
            auto timer = std::make_shared<net::steady_timer>(stream_.get_executor());
            timer->expires_after(std::chrono::milliseconds(1));
            timer->async_wait([self, state, timer](beast::error_code ec) {
                if (!ec) {
                    self->consume_stream(state);
                }
            });
            return;
        }
        
        // Send headers if needed
        if (need_headers) {
            std::string headers = "HTTP/1.1 200 OK\r\n"
                                  "Server: quickwork\r\n"
                                  "Content-Type: text/event-stream\r\n"
                                  "Cache-Control: no-cache\r\n"
                                  "Connection: close\r\n"
                                  "Transfer-Encoding: chunked\r\n"
                                  "\r\n";
            
            beast::error_code ec;
            net::write(stream_.socket(), net::buffer(headers), ec);
            if (ec) {
                std::cerr << "Error sending headers: " << ec.message() << "\n";
                return;
            }
        }
        
        // Send all chunks we grabbed
        for (const auto& chunk : chunks_to_send) {
            std::ostringstream oss;
            oss << std::hex << chunk.size() << "\r\n" << chunk << "\r\n";
            std::string chunk_data = oss.str();
            
            beast::error_code ec;
            net::write(stream_.socket(), net::buffer(chunk_data), ec);
            if (ec) {
                std::cerr << "Error sending chunk: " << ec.message() << "\n";
                return;
            }
        }
        
        // If we need to finish, send final chunk and close
        if (should_finish) {
            beast::error_code ec;
            const char final_chunk[] = "0\r\n\r\n";
            net::write(stream_.socket(), net::buffer(final_chunk, sizeof(final_chunk) - 1), ec);
            
            if (request_active_) {
                request_active_ = false;
                server_.request_finished();
            }
            
            do_close();
            return;
        }
        
        // Reschedule to check for more chunks
        if (should_reschedule) {
            auto self = shared_from_this();
            auto timer = std::make_shared<net::steady_timer>(stream_.get_executor());
            timer->expires_after(std::chrono::milliseconds(1));
            timer->async_wait([self, state, timer](beast::error_code ec) {
                if (!ec) {
                    self->consume_stream(state);
                }
            });
        }
    }

    void send_js_response(const HttpResponse& js_response, const ExecutionStats& stats) {
        http::response<http::string_body> res{
            static_cast<http::status>(js_response.status),
            request_.version()
        };
        res.set(http::field::server, "quickwork");
        res.keep_alive(request_.keep_alive());

        // Add execution stats headers
        std::ostringstream cpu_ss;
        cpu_ss << std::fixed << std::setprecision(2) << stats.cpu_time_ms;
        res.set("x-qw-cpu", cpu_ss.str());
        res.set("x-qw-mem", std::to_string(stats.memory_used / 1024));

        for (const auto& [key, value] : js_response.headers) {
            // Skip hop-by-hop headers that shouldn't be forwarded
            std::string lower_key = key;
            std::transform(lower_key.begin(), lower_key.end(), lower_key.begin(), ::tolower);
            if (lower_key == "connection" || lower_key == "keep-alive" ||
                lower_key == "transfer-encoding" || lower_key == "content-length") {
                continue;
            }
            // Strip server-exclusive header to prevent handlers from forging it
            if (lower_key == "x-qw-handler-not-found") {
                continue;
            }
            res.set(key, value);
        }

        res.body() = js_response.body;
        res.prepare_payload();

        send_response(std::move(res));
    }

    void send_error(unsigned status, std::string_view message, bool handler_not_found = false) {
        http::response<http::string_body> res{
            static_cast<http::status>(status),
            request_.version()
        };
        res.set(http::field::server, "quickwork");
        res.set(http::field::content_type, "application/json");
        if (handler_not_found) {
            res.set("x-qw-handler-not-found", "true");
        }
        res.keep_alive(request_.keep_alive());
        res.body() = R"({"error":")" + std::string(message) + R"("})";
        res.prepare_payload();

        send_response(std::move(res));
    }

    void send_response(http::response<http::string_body> res) {
        auto sp = std::make_shared<http::response<http::string_body>>(std::move(res));

        http::async_write(stream_, *sp,
            [self = shared_from_this(), sp](beast::error_code ec, std::size_t) {
                self->on_write(ec, sp->need_eof());
            });
    }

    void on_write(beast::error_code ec, bool close) {
        // Mark request as finished when response is sent
        if (request_active_) {
            request_active_ = false;
            server_.request_finished();
        }

        if (ec) {
            std::cerr << "Write error: " << ec.message() << "\n";
            return;
        }

        if (close) {
            return do_close();
        }

        do_read();
    }

    void do_close() {
        beast::error_code ec;
        stream_.socket().shutdown(tcp::socket::shutdown_send, ec);
    }

    beast::tcp_stream stream_;
    beast::flat_buffer buffer_;
    http::request<http::string_body> request_;
    Server& server_;
    HandlerStore& handler_store_;
    ThreadPool& thread_pool_;
    bool request_active_{false};
};

class Listener : public std::enable_shared_from_this<Listener> {
public:
    Listener(net::io_context& ioc, tcp::endpoint endpoint,
             Server& server, HandlerStore& store, ThreadPool& pool)
        : ioc_(ioc)
        , acceptor_(net::make_strand(ioc))
        , server_(server)
        , handler_store_(store)
        , thread_pool_(pool)
    {
        beast::error_code ec;

        acceptor_.open(endpoint.protocol(), ec);
        if (ec) {
            throw std::runtime_error("Failed to open acceptor: " + ec.message());
        }

        acceptor_.set_option(net::socket_base::reuse_address(true), ec);
        if (ec) {
            throw std::runtime_error("Failed to set reuse_address: " + ec.message());
        }

        acceptor_.bind(endpoint, ec);
        if (ec) {
            throw std::runtime_error("Failed to bind: " + ec.message());
        }

        acceptor_.listen(net::socket_base::max_listen_connections, ec);
        if (ec) {
            throw std::runtime_error("Failed to listen: " + ec.message());
        }
    }

    void run() {
        do_accept();
    }

private:
    void do_accept() {
        acceptor_.async_accept(
            net::make_strand(ioc_),
            beast::bind_front_handler(&Listener::on_accept, shared_from_this()));
    }

    void on_accept(beast::error_code ec, tcp::socket socket) {
        if (ec) {
            std::cerr << "Accept error: " << ec.message() << "\n";
        } else {
            std::make_shared<Session>(std::move(socket), server_, handler_store_, thread_pool_)->run();
        }

        do_accept();
    }

    net::io_context& ioc_;
    tcp::acceptor acceptor_;
    Server& server_;
    HandlerStore& handler_store_;
    ThreadPool& thread_pool_;
};

}  // namespace

Server::Server(const Config& config)
    : config_(config)
    , compiler_runtime_(std::make_unique<JsRuntime>(config_))
    , handler_store_(std::make_unique<HandlerStore>(config_))
    , thread_pool_(std::make_unique<ThreadPool>(config_))
{
    // In dev mode, load the handler immediately
    if (config_.dev_mode) {
        reload_dev_handler();
    }
}

Server::~Server() {
    stop();
}

std::string Server::store_handler(std::string_view source) {
    std::lock_guard<std::mutex> lock(compiler_mutex_);
    return handler_store_->store(compiler_runtime_->get(), source);
}

std::string Server::get_dev_handler_id() const {
    std::shared_lock lock(dev_handler_mutex_);
    return dev_handler_id_;
}

namespace {
// Check if file needs TypeScript/JSX compilation
bool needs_compilation(const std::filesystem::path& file) {
    std::string ext = file.extension().string();
    return ext == ".ts" || ext == ".tsx" || ext == ".jsx";
}

// Compile TypeScript/TSX/JSX to JavaScript using esbuild
std::optional<std::filesystem::path> compile_to_js(const std::filesystem::path& source_file) {
    namespace fs = std::filesystem;
    
    // Create output directory
    fs::path dist_dir = ".qw/dist";
    fs::create_directories(dist_dir);
    
    // Output file path (same name but .js extension)
    fs::path output_file = dist_dir / source_file.filename();
    output_file.replace_extension(".js");
    
    std::string source_path = source_file.string();
    std::string output_path = output_file.string();
    
    // Check for esbuild in node_modules
    fs::path esbuild_bin = "node_modules/.bin/esbuild";
    
    std::string esbuild_cmd = fs::exists(esbuild_bin) ? esbuild_bin.string() : "npx esbuild";
    
    // Build esbuild command with browser-compatible settings
    // - platform=browser: Use browser builds of packages (avoids Node.js-specific code)
    // - format=esm: Output ES modules
    // - bundle: Bundle all dependencies
    // - jsx=automatic: Use the new JSX transform (React 17+)
    // - external:https://*: Keep URL imports as-is (QuickWork's module resolver handles them at runtime)
    // - external:http://*: Same for http imports
    std::string cmd = esbuild_cmd +
          " \"" + source_path + "\"" +
          " --bundle"
          " --format=esm"
          " --platform=browser"
          " --target=es2020"
          " --outfile=\"" + output_path + "\""
          " --jsx=automatic"
          " --jsx-import-source=react"
          " --alias:react-dom/server=react-dom/server.browser"
          " --loader:.js=jsx"
          " --define:process.env.NODE_ENV=\\\"production\\\""
          " --external:https://*"
          " --external:http://*"
          " 2>&1";
    
    // Execute compilation
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) {
        std::cerr << "Failed to run compiler\n";
        return std::nullopt;
    }
    
    // Read output for error messages
    std::string output;
    char buffer[256];
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        output += buffer;
    }
    
    int status = pclose(pipe);
    
    if (status != 0) {
        std::cerr << "Compilation failed:\n" << output << "\n";
        return std::nullopt;
    }
    
    // Check if output file was created
    if (!fs::exists(output_file)) {
        std::cerr << "Compilation did not produce output file\n";
        return std::nullopt;
    }
    
    return output_file;
}
}  // namespace

void Server::reload_dev_handler() {
    namespace fs = std::filesystem;
    
    fs::path source_file = config_.dev_handler_file;
    fs::path file_to_load = source_file;
    
    // Check if we need to compile TypeScript/TSX/JSX
    if (needs_compilation(source_file)) {
        std::cout << "Compiling " << source_file << "...\n";
        auto compiled = compile_to_js(source_file);
        if (!compiled) {
            std::cerr << "Failed to compile " << source_file << "\n";
            return;
        }
        file_to_load = *compiled;
        std::cout << "Compiled to " << file_to_load << "\n";
    }
    
    // Read handler file (either original .js or compiled output)
    std::ifstream file(file_to_load);
    if (!file) {
        std::cerr << "Failed to read handler file: " << file_to_load << "\n";
        return;
    }

    std::ostringstream oss;
    oss << file.rdbuf();
    std::string source = oss.str();
    file.close();

    if (source.empty()) {
        std::cerr << "Handler file is empty: " << file_to_load << "\n";
        return;
    }

    try {
        std::string new_id = store_handler(source);
        
        {
            std::unique_lock lock(dev_handler_mutex_);
            dev_handler_id_ = new_id;
        }
        
        std::cout << "Loaded handler: " << config_.dev_handler_file << " -> " << new_id << "\n";
    } catch (const std::exception& e) {
        std::cerr << "Failed to compile handler: " << e.what() << "\n";
    }
}

void Server::watch_handler_file() {
    namespace fs = std::filesystem;
    
    auto last_write_time = fs::last_write_time(config_.dev_handler_file);
    
    while (watcher_running_) {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        
        if (!watcher_running_) break;
        
        try {
            auto current_write_time = fs::last_write_time(config_.dev_handler_file);
            
            if (current_write_time != last_write_time) {
                last_write_time = current_write_time;
                std::cout << "\nFile changed, reloading...\n";
                reload_dev_handler();
            }
        } catch (const std::exception& e) {
            // File might be temporarily unavailable during save
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
}

void Server::run() {
    running_ = true;

    // Start file watcher in dev mode
    if (config_.dev_mode) {
        watcher_running_ = true;
        file_watcher_thread_ = std::thread([this] { watch_handler_file(); });
    }

    // Start idle timeout watcher if configured
    if (config_.idle_timeout_seconds > 0) {
        idle_watcher_running_ = true;
        // Initialize last request time to now (treat server start as last activity)
        last_request_end_time_.store(std::chrono::steady_clock::now(), std::memory_order_relaxed);
        idle_timeout_thread_ = std::thread([this] { idle_timeout_watcher(); });
    }

    net::io_context ioc{static_cast<int>(config_.get_thread_count())};

    auto endpoint = tcp::endpoint{net::ip::make_address(config_.host), config_.port};

    std::make_shared<Listener>(ioc, endpoint, *this, *handler_store_, *thread_pool_)->run();

    std::cout << "Server listening on " << config_.host << ":" << config_.port << "\n";
    if (config_.dev_mode) {
        std::cout << "Watching for changes to " << config_.dev_handler_file << "...\n";
    }

    // Run the I/O context with multiple threads
    std::vector<std::thread> io_threads;
    const auto io_thread_count = std::max<size_t>(1, config_.get_thread_count() / 2);
    io_threads.reserve(io_thread_count);

    for (size_t i = 0; i < io_thread_count; ++i) {
        io_threads.emplace_back([&ioc] { ioc.run(); });
    }

    // Wait for threads
    for (auto& t : io_threads) {
        t.join();
    }
}

void Server::stop() {
    if (running_) {
        running_ = false;
        
        // Stop file watcher
        if (watcher_running_) {
            watcher_running_ = false;
            if (file_watcher_thread_.joinable()) {
                file_watcher_thread_.join();
            }
        }

        // Stop idle timeout watcher
        if (idle_watcher_running_) {
            idle_watcher_running_ = false;
            // Check if we're being called from the idle timeout thread itself
            // (happens when idle timeout triggers shutdown)
            if (idle_timeout_thread_.joinable()) {
                if (idle_timeout_thread_.get_id() == std::this_thread::get_id()) {
                    // We're in the idle timeout thread, detach instead of join
                    idle_timeout_thread_.detach();
                } else {
                    idle_timeout_thread_.join();
                }
            }
        }
        
        thread_pool_->shutdown();
    }
}

void Server::request_started() {
    active_requests_.fetch_add(1, std::memory_order_relaxed);
}

void Server::request_finished() {
    if (active_requests_.fetch_sub(1, std::memory_order_relaxed) == 1) {
        // Last request finished, update the timestamp
        last_request_end_time_.store(std::chrono::steady_clock::now(), std::memory_order_relaxed);
    }
}

void Server::idle_timeout_watcher() {
    const auto timeout = std::chrono::seconds(config_.idle_timeout_seconds);
    
    while (idle_watcher_running_) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        
        if (!idle_watcher_running_) break;
        
        // Check if there are no active requests
        if (active_requests_.load(std::memory_order_relaxed) == 0) {
            auto last_end = last_request_end_time_.load(std::memory_order_relaxed);
            auto now = std::chrono::steady_clock::now();
            
            if (now - last_end >= timeout) {
                std::cout << "\nIdle timeout reached (" << config_.idle_timeout_seconds << "s), shutting down...\n";
                // Signal the process to exit
                std::raise(SIGTERM);
                break;
            }
        }
    }
}

}  // namespace quickwork
