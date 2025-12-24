#pragma once

#include "config.hpp"
#include "js_runtime.hpp"

#include <condition_variable>
#include <functional>
#include <future>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

namespace quickwork {

class ThreadPool {
public:
    explicit ThreadPool(const Config& config);
    ~ThreadPool();

    ThreadPool(const ThreadPool&) = delete;
    ThreadPool& operator=(const ThreadPool&) = delete;
    ThreadPool(ThreadPool&&) = delete;
    ThreadPool& operator=(ThreadPool&&) = delete;

    template <typename F, typename... Args>
    auto enqueue(F&& f, Args&&... args)
        -> std::future<std::invoke_result_t<F, JsRuntime&, Args...>>;

    void shutdown();

private:
    void worker_thread(size_t thread_id);

    const Config& config_;
    std::vector<std::thread> workers_;
    std::queue<std::function<void(JsRuntime&)>> tasks_;

    std::mutex queue_mutex_;
    std::condition_variable condition_;
    bool stop_ = false;
};

template <typename F, typename... Args>
auto ThreadPool::enqueue(F&& f, Args&&... args)
    -> std::future<std::invoke_result_t<F, JsRuntime&, Args...>>
{
    using return_type = std::invoke_result_t<F, JsRuntime&, Args...>;

    auto task = std::make_shared<std::packaged_task<return_type(JsRuntime&)>>(
        [func = std::forward<F>(f), ... captured_args = std::forward<Args>(args)]
        (JsRuntime& rt) mutable {
            return func(rt, std::forward<Args>(captured_args)...);
        }
    );

    std::future<return_type> result = task->get_future();
    {
        std::unique_lock lock(queue_mutex_);
        if (stop_) {
            throw std::runtime_error("enqueue on stopped ThreadPool");
        }
        tasks_.emplace([task = std::move(task)](JsRuntime& rt) {
            (*task)(rt);
        });
    }
    condition_.notify_one();
    return result;
}

}  // namespace quickwork
