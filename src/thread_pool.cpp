#include "thread_pool.hpp"
#include "js_bindings.hpp"

#include <iostream>
#include <list>

namespace quickwork {

ThreadPool::ThreadPool(const Config& config) : config_(config) {
    const size_t num_threads = config_.get_thread_count();

    workers_.reserve(num_threads);
    for (size_t i = 0; i < num_threads; ++i) {
        workers_.emplace_back(&ThreadPool::worker_thread, this, i);
    }

    std::cout << "Thread pool started with " << num_threads << " worker threads\n";
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

void ThreadPool::enqueue_handler(Bytecode bytecode, HttpRequest request,
                                  std::function<void(ExecutionResult)> callback,
                                  StreamWriter stream_writer) {
    {
        std::unique_lock<std::mutex> lock(queue_mutex_);
        if (stop_) return;
        new_tasks_.push(NewTask{std::move(bytecode), std::move(request), 
                                std::move(callback), std::move(stream_writer)});
    }
    condition_.notify_one();
}

void ThreadPool::worker_thread(size_t thread_id) {
    // Each thread gets its own QuickJS runtime
    JsRuntime runtime(config_);

    std::cout << "Worker thread " << thread_id << " started\n";

    // List of in-flight async tasks for this thread
    std::list<AsyncTask> in_flight;

    while (true) {
        // Try to get new tasks without blocking if we have in-flight work
        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            
            if (in_flight.empty()) {
                // No in-flight work, block until we get something
                condition_.wait(lock, [this] {
                    return stop_ || !tasks_.empty() || !new_tasks_.empty();
                });
            }

            if (stop_ && tasks_.empty() && new_tasks_.empty() && in_flight.empty()) {
                return;
            }

            // Process all available legacy tasks first
            while (!tasks_.empty()) {
                auto task = std::move(tasks_.front());
                tasks_.pop();
                lock.unlock();
                
                try {
                    task(runtime);
                } catch (const std::exception& e) {
                    std::cerr << "Task error in thread " << thread_id << ": " << e.what() << "\n";
                }
                
                lock.lock();
            }

            // Pick up new handler tasks and start them
            while (!new_tasks_.empty()) {
                auto new_task = std::move(new_tasks_.front());
                new_tasks_.pop();
                lock.unlock();

                try {
                    // Set up stream writer before creating context (thread-local)
                    if (new_task.stream_writer) {
                        bindings::set_stream_writer(nullptr, new_task.stream_writer);
                    }
                    
                    auto ctx = std::make_unique<JsContext>(runtime.create_context());
                    bool done = ctx->start_handler(new_task.bytecode, new_task.request);
                    
                    if (done) {
                        // Completed synchronously - clear stream writer
                        bindings::set_stream_writer(nullptr, nullptr);
                        new_task.callback(ctx->get_result());
                    } else {
                        // Needs async polling - keep stream writer in AsyncTask
                        in_flight.emplace_back(std::move(ctx), std::move(new_task.callback),
                                               std::move(new_task.stream_writer));
                    }
                } catch (const std::exception& e) {
                    std::cerr << "Handler start error in thread " << thread_id << ": " << e.what() << "\n";
                    bindings::set_stream_writer(nullptr, nullptr);
                    ExecutionResult error_result;
                    error_result.error = e.what();
                    new_task.callback(std::move(error_result));
                }

                lock.lock();
            }
        }

        // Poll all in-flight tasks
        for (auto it = in_flight.begin(); it != in_flight.end(); ) {
            try {
                // Restore stream writer for this task's context before polling
                if (it->stream_writer) {
                    bindings::set_stream_writer(nullptr, it->stream_writer);
                }
                
                if (it->context->poll()) {
                    // Task completed - clear stream writer
                    bindings::set_stream_writer(nullptr, nullptr);
                    it->callback(it->context->get_result());
                    it = in_flight.erase(it);
                } else {
                    ++it;
                }
            } catch (const std::exception& e) {
                std::cerr << "Poll error in thread " << thread_id << ": " << e.what() << "\n";
                bindings::set_stream_writer(nullptr, nullptr);
                ExecutionResult error_result;
                error_result.error = e.what();
                it->callback(std::move(error_result));
                it = in_flight.erase(it);
            }
        }

        // Small sleep to avoid busy-waiting when we have in-flight tasks
        // but no progress was made
        if (!in_flight.empty()) {
            std::this_thread::sleep_for(std::chrono::microseconds(100));
        }
    }
}

}  // namespace quickwork
