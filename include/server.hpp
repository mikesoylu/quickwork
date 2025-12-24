#pragma once

#include "config.hpp"
#include "handler_store.hpp"
#include "thread_pool.hpp"

#include <memory>
#include <string>

namespace quickwork {

class Server {
public:
    explicit Server(const Config& config);
    ~Server();

    Server(const Server&) = delete;
    Server& operator=(const Server&) = delete;
    Server(Server&&) = delete;
    Server& operator=(Server&&) = delete;

    void run();
    void stop();

private:
    Config config_;
    std::unique_ptr<HandlerStore> handler_store_;
    std::unique_ptr<ThreadPool> thread_pool_;
    bool running_ = false;
};

}  // namespace quickwork
