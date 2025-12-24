#include "server.hpp"
#include "js_runtime.hpp"

#include <boost/asio.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>

#include <iomanip>
#include <iostream>
#include <memory>

namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
using tcp = net::ip::tcp;

namespace quickwork {

namespace {

class Session : public std::enable_shared_from_this<Session> {
public:
    Session(tcp::socket socket, HandlerStore& store, ThreadPool& pool)
        : stream_(std::move(socket))
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

            std::string id = handler_store_.store(source);

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
        auto source_opt = handler_store_.load(handler_id);
        if (!source_opt) {
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

        std::string source = *source_opt;
        std::string url = js_request.url;

        // Execute in thread pool
        auto self = shared_from_this();
        auto future = thread_pool_.enqueue(
            [source = std::move(source), js_request = std::move(js_request)]
            (JsRuntime& runtime) -> ExecutionResult {
                auto ctx = runtime.create_context();
                return ctx.execute_handler(source, js_request);
            }
        );

        // We need to handle this asynchronously
        // For simplicity, we'll use a detached thread to wait for the result
        std::thread([self, future = std::move(future), handler_id, url]() mutable {
            try {
                auto result = future.get();
                
                // Print stats
                std::cout << "[" << handler_id << "] " << url 
                          << " | cpu: " << std::fixed << std::setprecision(2) << result.stats.cpu_time_ms << "ms"
                          << " | mem: " << (result.stats.memory_used / 1024) << "KB"
                          << "\n";
                
                if (result.response) {
                    self->send_js_response(*result.response);
                } else {
                    self->send_error(500, result.error.empty() ? "Handler execution failed" : result.error);
                }
            } catch (const std::exception& e) {
                self->send_error(500, e.what());
            }
        }).detach();
    }

    void send_js_response(const HttpResponse& js_response) {
        http::response<http::string_body> res{
            static_cast<http::status>(js_response.status),
            request_.version()
        };
        res.set(http::field::server, "quickwork");
        res.keep_alive(request_.keep_alive());

        for (const auto& [key, value] : js_response.headers) {
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
    HandlerStore& handler_store_;
    ThreadPool& thread_pool_;
};

class Listener : public std::enable_shared_from_this<Listener> {
public:
    Listener(net::io_context& ioc, tcp::endpoint endpoint,
             HandlerStore& store, ThreadPool& pool)
        : ioc_(ioc)
        , acceptor_(net::make_strand(ioc))
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
            std::make_shared<Session>(std::move(socket), handler_store_, thread_pool_)->run();
        }

        do_accept();
    }

    net::io_context& ioc_;
    tcp::acceptor acceptor_;
    HandlerStore& handler_store_;
    ThreadPool& thread_pool_;
};

}  // namespace

Server::Server(const Config& config)
    : config_(config)
    , handler_store_(std::make_unique<HandlerStore>(config_))
    , thread_pool_(std::make_unique<ThreadPool>(config_))
{
}

Server::~Server() {
    stop();
}

void Server::run() {
    running_ = true;

    net::io_context ioc{static_cast<int>(config_.get_thread_count())};

    auto endpoint = tcp::endpoint{net::ip::make_address(config_.host), config_.port};

    std::make_shared<Listener>(ioc, endpoint, *handler_store_, *thread_pool_)->run();

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
