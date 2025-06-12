#include "backpressure.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <algorithm>
#include <cmath>

// --- PIDController 实现 ---
PIDController::PIDController(double kp, double ki, double kd, double dt)
    : kp_(kp), ki_(ki), kd_(kd), dt_(dt), prev_error_(0.0), integral_(0.0) {}

double PIDController::update(double error) {
    integral_ += error * dt_;
    double derivative = (error - prev_error_) / dt_;
    double output = kp_ * error + ki_ * integral_ + kd_ * derivative;
    prev_error_ = error;
    return output;
}

// --- MemoryGovernor 实现 ---

MemoryGovernor::MemoryGovernor() : maxMemoryBytes_(0) {
    std::ifstream meminfo("/proc/meminfo");
    if (!meminfo) {
        std::cerr << "Failed to open /proc/meminfo" << std::endl;
        return;
    }

    std::string line;
    while (std::getline(meminfo, line)) {
        if (line.find("MemTotal:") == 0) {
            size_t kb = 0;
            sscanf(line.c_str(), "MemTotal: %lu kB", &kb);
            maxMemoryBytes_ = kb * 1024;
            break;
        }
    }

    if (maxMemoryBytes_ == 0) {
        std::cerr << "Failed to parse MemTotal from /proc/meminfo" << std::endl;
    }
}

size_t MemoryGovernor::getCurrentMemoryUsage() const {
    std::ifstream meminfo("/proc/meminfo");
    if (!meminfo) return 0;

    size_t memTotalKB = 0;
    size_t memAvailableKB = 0;
    std::string line;

    while (std::getline(meminfo, line)) {
        if (line.find("MemTotal:") == 0)
            sscanf(line.c_str(), "MemTotal: %lu kB", &memTotalKB);
        else if (line.find("MemAvailable:") == 0)
            sscanf(line.c_str(), "MemAvailable: %lu kB", &memAvailableKB);
    }

    if (memTotalKB == 0 || memAvailableKB == 0)
        return 0;

    return (memTotalKB - memAvailableKB) * 1024;
}

bool MemoryGovernor::isMemoryPressureHigh() const {
    size_t used = getCurrentMemoryUsage();
    return used > maxMemoryBytes_ * 0.7;
}

bool MemoryGovernor::isMemoryPressureCritical() const {
    size_t used = getCurrentMemoryUsage();
    return used > maxMemoryBytes_ * 0.9;
}

// --- AdaptiveBackpressure 实现 ---

AdaptiveBackpressure::AdaptiveBackpressure(size_t maxQueueLength)
    : memGovernor_(),
      pidController_(0.5, 0.1, 0.05, 1.0),
      currentQueueLength_(0),
      currentMemoryUsage_(0),
      state_(BackpressureState::NORMAL),
      baseDelayMs_(5),
      maxDelayMs_(200) {}

void AdaptiveBackpressure::updateStats(size_t currentQueueLength) {
    currentQueueLength_.store(currentQueueLength, std::memory_order_relaxed);
    size_t memUsed = memGovernor_.getCurrentMemoryUsage();
    currentMemoryUsage_.store(memUsed, std::memory_order_relaxed);
    updateState();
}

void AdaptiveBackpressure::updateState() {
    size_t memUse = currentMemoryUsage_.load(std::memory_order_relaxed);
    size_t totalMem = memGovernor_.getTotalMemoryBytes();
    size_t queueLen = currentQueueLength_.load(std::memory_order_relaxed);

    double memRatio = totalMem > 0 ? (double)memUse / totalMem : 0;

    if (memRatio > 0.9 || queueLen > 10000) {
        state_ = BackpressureState::STOP_PRODUCTION;
    } else if (memRatio > 0.8 || queueLen > 5000) {
        state_ = BackpressureState::HEAVY_PRESSURE;
    } else if (memRatio > 0.7 || queueLen > 1000) {
        state_ = BackpressureState::LIGHT_PRESSURE;
    } else {
        state_ = BackpressureState::NORMAL;
    }
}

int AdaptiveBackpressure::calculateDelay() {
    double targetDelay = 0.0;
    switch (state_) {
    case BackpressureState::NORMAL:
        targetDelay = baseDelayMs_ * 0.5;
        break;
    case BackpressureState::LIGHT_PRESSURE:
        targetDelay = baseDelayMs_ * 5;
        break;
    case BackpressureState::HEAVY_PRESSURE:
        targetDelay = maxDelayMs_ * 0.7;
        break;
    case BackpressureState::STOP_PRODUCTION:
        targetDelay = maxDelayMs_;
        break;
    }

    static double lastDelay = 0;
    double error = targetDelay - lastDelay;
    double adjusted = pidController_.update(error);
    double newDelay = lastDelay + adjusted;

    newDelay = std::max(0.0, std::min(static_cast<double>(maxDelayMs_), newDelay));
    lastDelay = newDelay;

    return static_cast<int>(newDelay);
}

int AdaptiveBackpressure::getDelayMs() {
    return calculateDelay();
}

BackpressureState AdaptiveBackpressure::getState() const {
    return state_;
}
void AdaptiveBackpressure::logStatus() const {
    std::string stateStr;
    switch (state_) {
        case BackpressureState::NORMAL: stateStr = "NORMAL"; break;
        case BackpressureState::LIGHT_PRESSURE: stateStr = "LIGHT_PRESSURE"; break;
        case BackpressureState::HEAVY_PRESSURE: stateStr = "HEAVY_PRESSURE"; break;
        case BackpressureState::STOP_PRODUCTION: stateStr = "STOP_PRODUCTION"; break;
    }
    std::cout << "[Backpressure] State: " << stateStr
              << ", Queue: " << currentQueueLength_
              << ", Memory: " << memGovernor_.getMemoryUsageRatio() * 100 << "%"
              << std::endl;
}

double MemoryGovernor::getUsedMemoryMB() const {
    struct sysinfo memInfo;
    sysinfo(&memInfo);
    long long totalVirtualMem = memInfo.totalram;
    totalVirtualMem += memInfo.totalswap;
    totalVirtualMem *= memInfo.mem_unit;

    long long virtualMemUsed = memInfo.totalram - memInfo.freeram;
    virtualMemUsed *= memInfo.mem_unit;

    return virtualMemUsed / (1024.0 * 1024.0); // MB
}

double MemoryGovernor::getTotalMemoryMB() const {
    struct sysinfo memInfo;
    sysinfo(&memInfo);
    long long totalRAM = memInfo.totalram;
    totalRAM *= memInfo.mem_unit;
    return totalRAM / (1024.0 * 1024.0); // MB
}