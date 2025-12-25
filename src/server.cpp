#include "server.hpp"
#include "js_runtime.hpp"
#include "js_bindings.hpp"

#include <boost/asio.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <iomanip>
#include <iostream>
#include <memory>
#include <mutex>
#include <queue>

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
            // Handler loader endpoint
            handle_loader();
        } else if (handler_id_it != request_.end()) {
            // Execute handler
            handle_execute(std::string(handler_id_it->value()));
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
            send_error(404, "Handler not found");
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
            res.set(key, value);
        }

        res.body() = js_response.body;
        res.prepare_payload();

        send_response(std::move(res));
    }

    void send_error(unsigned status, std::string_view message) {
        http::response<http::string_body> res{
            static_cast<http::status>(status),
            request_.version()
        };
        res.set(http::field::server, "quickwork");
        res.set(http::field::content_type, "application/json");
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
}

Server::~Server() {
    stop();
}

std::string Server::store_handler(std::string_view source) {
    std::lock_guard<std::mutex> lock(compiler_mutex_);
    return handler_store_->store(compiler_runtime_->get(), source);
}

void Server::run() {
    running_ = true;

    net::io_context ioc{static_cast<int>(config_.get_thread_count())};

    auto endpoint = tcp::endpoint{net::ip::make_address(config_.host), config_.port};

    std::make_shared<Listener>(ioc, endpoint, *this, *handler_store_, *thread_pool_)->run();

    std::cout << "Server listening on " << config_.host << ":" << config_.port << "\n";

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
        thread_pool_->shutdown();
    }
}

}  // namespace quickwork
