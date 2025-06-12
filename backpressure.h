#ifndef BACKPRESSURE_H
#define BACKPRESSURE_H

#include <atomic>
#include <chrono>
#include <thread>
#include <mutex>
#include <cstddef>
#include <vector>
#include <string>
#include <queue>
#include <memory>
#include <condition_variable>
#include <sodium.h>
#include <sys/sysinfo.h>
#include <cassert>
// 必须添加常量定义
constexpr size_t BATCH_SIZE = 128;
constexpr size_t DERIVED_KEYS_PER_SEED = 5;

// 改进BatchTask的内存管理
struct ImprovedBatchTask {
    std::vector<std::vector<uint8_t>> private_keys;
    std::vector<std::vector<uint8_t>> public_keys;
    std::vector<std::string> addresses;
    std::chrono::steady_clock::time_point creation_time;
    
    ImprovedBatchTask() {
        creation_time = std::chrono::steady_clock::now();
        private_keys.reserve(BATCH_SIZE * DERIVED_KEYS_PER_SEED);
        public_keys.reserve(BATCH_SIZE * DERIVED_KEYS_PER_SEED);
        addresses.reserve(BATCH_SIZE * DERIVED_KEYS_PER_SEED);
    }
    
    ~ImprovedBatchTask() {
        // 安全清除所有私钥
        for (auto& key : private_keys) {
            if (!key.empty()) {
                sodium_memzero(key.data(), key.size());
            }
        }
    }
// 获取任务存活时间
    double get_age_seconds() const {
        auto now = std::chrono::steady_clock::now();
        return std::chrono::duration<double>(now - creation_time).count();
    }
    
    // 估算内存使用量
    size_t estimate_memory_usage() const {
        size_t total = 0;
        for (const auto& key : private_keys) {
            total += key.capacity();
        }
        for (const auto& key : public_keys) {
            total += key.capacity();
        }
        for (const auto& addr : addresses) {
            total += addr.capacity();
        }
        return total;
    }
};
enum class BackpressureState {
    NORMAL,
    LIGHT_PRESSURE,
    HEAVY_PRESSURE,
    STOP_PRODUCTION
};

class PIDController {
public:
    PIDController(double kp, double ki, double kd, double dt);
    double update(double error);

private:
    double kp_, ki_, kd_;
    double dt_;
    double prev_error_;
    double integral_;
};

class MemoryGovernor {
public:
    MemoryGovernor();
    // 添加这个函数
    double getMemoryUsageRatio() const {
        return static_cast<double>(getUsedMemoryMB()) / getTotalMemoryMB();
    }

    double getUsedMemoryMB() const;
    double getTotalMemoryMB() const;

    // 获取系统当前实际使用内存 (单位: bytes)
    size_t getCurrentMemoryUsage() const;

    // 是否达到高压或临界压
    bool isMemoryPressureHigh() const;
    bool isMemoryPressureCritical() const;

    // 获取系统总内存
    size_t getTotalMemoryBytes() const { return maxMemoryBytes_; }

private:
    size_t maxMemoryBytes_;  // 系统总内存 (bytes)
};

class AdaptiveBackpressure {
public:
    AdaptiveBackpressure(size_t maxQueueLength);
    void updateStats(size_t currentQueueLength);
    int getDelayMs();
    BackpressureState getState() const;
    void logStatus() const;

private:
    void updateState();
    int calculateDelay();

    MemoryGovernor memGovernor_;
    PIDController pidController_;
    std::atomic<size_t> currentQueueLength_;
    std::atomic<size_t> currentMemoryUsage_;
    BackpressureState state_;
    int baseDelayMs_;
    int maxDelayMs_;
};

// MonitoredQueue 模板：用于监控任务队列长度
template<typename T>
class LockFreeQueue {
public:
    explicit LockFreeQueue(size_t capacity)
        : capacity_(capacity), buffer_(capacity) {
        assert((capacity & (capacity - 1)) == 0 && "Capacity must be power of 2.");
        head_.store(0);
        tail_.store(0);
    }

    // 多线程安全入队，成功返回 true，失败（队列满）返回 false
    bool enqueue(const T& item) {
        size_t tail = tail_.load(std::memory_order_relaxed);
        size_t next_tail = increment(tail);
        if (next_tail == head_.load(std::memory_order_acquire)) {
            return false; // full
        }
        buffer_[tail] = item;
        tail_.store(next_tail, std::memory_order_release);
        return true;
    }

    // 多线程安全出队，成功将 item 设置为队首元素，返回 true，失败（空）返回 false
    bool dequeue(T& item) {
        size_t head = head_.load(std::memory_order_relaxed);
        if (head == tail_.load(std::memory_order_acquire)) {
            return false; // empty
        }
        item = buffer_[head];
        head_.store(increment(head), std::memory_order_release);
        return true;
    }

    size_t size() const {
        size_t tail = tail_.load(std::memory_order_acquire);
        size_t head = head_.load(std::memory_order_acquire);
        return (tail + capacity_ - head) & (capacity_ - 1);
    }

    size_t capacity() const {
        return capacity_ - 1;
    }
    bool empty() const {
    return size() == 0;
}

private:
    size_t increment(size_t idx) const {
        return (idx + 1) & (capacity_ - 1);
    }

    const size_t capacity_;
    std::vector<T> buffer_;
    std::atomic<size_t> head_;
    std::atomic<size_t> tail_;
};
#endif // BACKPRESSURE_H
