#include "thread_pool.hpp"

#include <iostream>

namespace quickwork {

ThreadPool::ThreadPool(const Config& config) : config_(config) {
    const size_t num_threads = config_.get_thread_count();

    workers_.reserve(num_threads);
    for (size_t i = 0; i < num_threads; ++i) {
        workers_.emplace_back(&ThreadPool::worker_thread, this, i);
    }

    std::cout << "Thread pool started with " << num_threads << " threads\n";
}

ThreadPool::~ThreadPool() {
    shutdown();
}

void ThreadPool::shutdown() {
    {
        std::unique_lock<std::mutex> lock(queue_mutex_);
        if (stop_) return;
        stop_ = true;
    }
    condition_.notify_all();

    for (auto& worker : workers_) {
        if (worker.joinable()) {
            worker.join();
        }
    }
}

void ThreadPool::worker_thread(size_t thread_id) {
    // Each thread gets its own QuickJS runtime
    JsRuntime runtime(config_);

    std::cout << "Worker thread " << thread_id << " started\n";

    while (true) {
        std::function<void(JsRuntime&)> task;

        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            condition_.wait(lock, [this] {
                return stop_ || !tasks_.empty();
            });

            if (stop_ && tasks_.empty()) {
                return;
            }

            task = std::move(tasks_.front());
            tasks_.pop();
        }

        try {
            task(runtime);
        } catch (const std::exception& e) {
            std::cerr << "Task error in thread " << thread_id << ": " << e.what() << "\n";
        }
    }
}

}  // namespace quickwork
