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
#include <sstream>

namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
using tcp = net::ip::tcp;

namespace quickwork {

namespace {

class Session : public std::enable_shared_from_this<Session> {
public:
    Session(tcp::socket socket, Server& server, HandlerStore& store, ThreadPool& pool)
        : stream_(std::move(socket))
        , server_(server)
        , handler_store_(store)
        , thread_pool_(pool)
    {
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

        if (request_.method() == http::verb::post && handler_id_it == request_.end()) {
            // Handler loader endpoint (disabled in dev mode)
            if (server_.is_dev_mode()) {
                send_error(400, "Handler registration disabled in dev mode");
                return;
            }
            handle_loader();
        } else if (handler_id_it != request_.end()) {
            // Execute handler by ID
            handle_execute(std::string(handler_id_it->value()));
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
            send_error(400, "Missing x-handler-id header");
        }
    }

    void handle_loader() {
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

        // Execute on thread pool with streaming support
        auto self = shared_from_this();
        
        // Shared state for streaming
        auto streaming_state = std::make_shared<StreamingState>();
        
        thread_pool_.enqueue_with_callback(
            [self, bytecode = std::move(bytecode), js_request = std::move(js_request), streaming_state]
            (JsRuntime& runtime) -> ExecutionResult {
                // Set up stream writer that queues chunks
                bindings::set_stream_writer(nullptr, [self, streaming_state](std::string_view chunk) {
                    std::lock_guard<std::mutex> lock(streaming_state->mutex);
                    streaming_state->chunks.push(std::string(chunk));
                    streaming_state->has_data = true;
                    streaming_state->cv.notify_one();
                });
                
                auto ctx = runtime.create_context();
                auto result = ctx.execute_handler(bytecode, js_request);
                
                // Signal streaming complete
                {
                    std::lock_guard<std::mutex> lock(streaming_state->mutex);
                    streaming_state->complete = true;
                    streaming_state->cv.notify_one();
                }
                
                // Clear stream writer
                bindings::set_stream_writer(nullptr, nullptr);
                
                return result;
            },
            [self, streaming_state](ExecutionResult result) {
                // Check if this was a streaming response
                if (streaming_state->has_data) {
                    // Streaming was handled separately
                    return;
                }
                
                if (result.response) {
                    self->send_js_response(*result.response, result.stats);
                } else {
                    self->send_error(500, result.error.empty() ? "Handler execution failed" : result.error);
                }
            }
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
    };
    
    void consume_stream(std::shared_ptr<StreamingState> state) {
        // Wait for first chunk or completion
        std::unique_lock<std::mutex> lock(state->mutex);
        
        // Wait until we have streaming data or the handler completes
        while (!state->has_data && !state->complete) {
            state->cv.wait_for(lock, std::chrono::milliseconds(100));
        }
        
        // If no streaming data and complete, let the regular callback handle it
        if (!state->has_data && state->complete) {
            return;
        }
        
        // Send headers if not sent yet (only if we have streaming data)
        if (!state->headers_sent && state->has_data) {
            state->headers_sent = true;
            lock.unlock();
            
            // Send chunked response headers
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
            
            lock.lock();
        }
        
        // Process chunks
        while (true) {
            // Wait for chunk or completion
            state->cv.wait_for(lock, std::chrono::milliseconds(50), [&state] {
                return !state->chunks.empty() || state->complete;
            });
            
            // Send all available chunks
            while (!state->chunks.empty()) {
                std::string chunk = std::move(state->chunks.front());
                state->chunks.pop();
                lock.unlock();
                
                // Send chunk in HTTP chunked format
                std::ostringstream oss;
                oss << std::hex << chunk.size() << "\r\n" << chunk << "\r\n";
                std::string chunk_data = oss.str();
                
                beast::error_code ec;
                net::write(stream_.socket(), net::buffer(chunk_data), ec);
                if (ec) {
                    std::cerr << "Error sending chunk: " << ec.message() << "\n";
                    return;
                }
                
                lock.lock();
            }
            
            // Check if complete
            if (state->complete && state->chunks.empty()) {
                break;
            }
        }
        
        lock.unlock();
        
        // Send final chunk
        beast::error_code ec;
        net::write(stream_.socket(), net::buffer("0\r\n\r\n"), ec);
        
        // Close connection
        do_close();
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
    
    // Create polyfill shim file for React DOM compatibility
    // This provides MessageChannel and other APIs needed by React's server renderer
    fs::path shim_file = dist_dir / "_qw_shim.js";
    {
        std::ofstream shim(shim_file);
        shim << R"JS(// QuickWork React DOM compatibility shim
if (typeof MessageChannel === 'undefined') {
    globalThis.MessageChannel = class MessageChannel {
        constructor() {
            this.port1 = { postMessage: () => {}, onmessage: null, close: () => {} };
            this.port2 = { postMessage: () => {}, onmessage: null, close: () => {} };
            // Connect ports
            this.port1.postMessage = (msg) => {
                if (this.port2.onmessage) {
                    setTimeout(() => this.port2.onmessage({ data: msg }), 0);
                }
            };
            this.port2.postMessage = (msg) => {
                if (this.port1.onmessage) {
                    setTimeout(() => this.port1.onmessage({ data: msg }), 0);
                }
            };
        }
    };
}

if (typeof setImmediate === 'undefined') {
    globalThis.setImmediate = (fn, ...args) => setTimeout(fn, 0, ...args);
    globalThis.clearImmediate = (id) => clearTimeout(id);
}

if (typeof queueMicrotask === 'undefined') {
    globalThis.queueMicrotask = (fn) => Promise.resolve().then(fn);
}

// Mark this as NOT a React Server Components environment
// This allows react-dom/server to be used normally
globalThis.__REACT_SERVER_CONTEXT__ = false;
)JS";
        shim.close();
    }
    
    // Create alias file to redirect react-dom/server to the static build
    fs::path alias_file = dist_dir / "_qw_alias.json";
    {
        std::ofstream alias(alias_file);
        alias << R"JSON({
  "react-dom/server": "react-dom/server.browser"
}
)JSON";
        alias.close();
    }
    
    // Check for esbuild in node_modules
    fs::path esbuild_bin = "node_modules/.bin/esbuild";
    
    std::string esbuild_cmd = fs::exists(esbuild_bin) ? esbuild_bin.string() : "npx esbuild";
    
    // Build esbuild command with browser-compatible settings
    // - platform=browser: Use browser builds of packages (avoids Node.js-specific code)
    // - format=esm: Output ES modules
    // - bundle: Bundle all dependencies
    // - jsx=automatic: Use the new JSX transform (React 17+)
    // - inject: Include our shim file to polyfill MessageChannel etc.
    // - alias: Redirect react-dom/server to browser build to avoid RSC errors
    std::string cmd = esbuild_cmd +
          " \"" + source_path + "\"" +
          " --bundle"
          " --format=esm"
          " --platform=browser"
          " --target=es2020"
          " --outfile=\"" + output_path + "\""
          " --jsx=automatic"
          " --jsx-import-source=react"
          " --inject:\"" + shim_file.string() + "\""
          " --alias:react-dom/server=react-dom/server.browser"
          " --conditions=browser,import,default"
          " --main-fields=browser,module,main"
          " --loader:.js=jsx"
          " --define:process.env.NODE_ENV=\\\"production\\\""
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
        
        thread_pool_->shutdown();
    }
}

}  // namespace quickwork
