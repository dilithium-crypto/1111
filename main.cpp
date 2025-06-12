#include <cstring>
#include <csignal>
#include <iostream>
#include <vector>
#include <thread>
#include <atomic>
#include <regex>
#include <array>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <memory>
#include <chrono>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <random>
#include <algorithm>
#include <immintrin.h>
#include <unordered_set>
#include <sys/mman.h>
#include <limits>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/provider.h>
#include <openssl/conf.h>
#include <openssl/engine.h>

#include <sodium.h>
#include <secp256k1.h>
#include <secp256k1_recovery.h>
#include <libbase58.h>
#include "backpressure.h"

extern "C" {
#include <openssl/sha.h>
#include "align.h"
#include "brg_endian.h"
#include "config.h"
#include "SIMD256-config.h"
}

// 全局变量
AdaptiveBackpressure* g_backpressure_controller = nullptr;

// 配置参数
constexpr size_t MEMORY_POOL_BLOCK_SIZE = 512 * 1024;
constexpr size_t MEMORY_POOL_MAX_BLOCKS = 400;
constexpr size_t MEMORY_POOL_MAX_SIZE = MEMORY_POOL_BLOCK_SIZE * MEMORY_POOL_MAX_BLOCKS;
constexpr size_t MEMORY_POOL_WARNING_SIZE = MEMORY_POOL_MAX_SIZE * 0.7;

static const size_t HARDWARE_THREADS = std::thread::hardware_concurrency();
constexpr size_t MONITOR_THREADS = 1;
size_t PRODUCER_THREADS = std::max<size_t>(1, HARDWARE_THREADS / 4);
size_t CONSUMER_THREADS = std::max<size_t>(1, HARDWARE_THREADS - PRODUCER_THREADS - MONITOR_THREADS);
//constexpr size_t BATCH_SIZE = 64;
constexpr size_t MAX_QUEUE_SIZE = 10000;
constexpr size_t CACHE_LINE_SIZE = 64;

constexpr size_t MAX_MEMORY_USAGE = 12ULL * 1024 * 1024 * 1024;
std::atomic<size_t> current_memory_usage{0};

// 全局状态
struct alignas(CACHE_LINE_SIZE) GlobalState {
    std::atomic<bool> running{true};
    std::atomic<uint64_t> keys_generated{0}; 
    std::atomic<uint64_t> addresses_checked{0}; 
    std::atomic<uint64_t> matches_found{0}; 
    std::unordered_set<std::string> target_addresses;
    std::string result_file;
    mutable std::mutex file_mutex;
} global_state;

// 比特币配置（支持任意长度范围）
struct BitcoinConfig {
    bool use_compressed;
    std::string target_file;  // 更改为目标文件路径
    std::string result_file;
    std::vector<uint8_t> start_range;     // 任意长度起始范围
    std::vector<uint8_t> end_range;       // 任意长度结束范围
    bool use_custom_range{false};         // 是否使用自定义范围
    bool is_256bit_range{false};          // 是否为256位范围
    std::vector<uint8_t> current_key;     // 当前生成的私钥（用于连续递增）
} btc_config;

// 声明
std::vector<uint8_t> compute_checksum(const uint8_t* data, size_t len);

// 定义
std::vector<uint8_t> compute_checksum(const uint8_t* data, size_t len) {
    std::vector<uint8_t> hash(32);
    SHA256(data, len, hash.data());
    SHA256(hash.data(), hash.size(), hash.data());
    return std::vector<uint8_t>(hash.begin(), hash.begin() + 4);
}

class PrivateKeyRange {
private:
    std::vector<uint8_t> start;
    std::vector<uint8_t> end;
    std::vector<uint8_t> current;
    uint64_t total_keys;       // 总密钥数量
    uint64_t searched_keys;    // 已搜索密钥数量
    double start_percent;      // 起始百分比

    // 比较两个私钥
    static int compare(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
        if (a.size() != b.size())
            return a.size() < b.size() ? -1 : 1;
            
        for (size_t i = 0; i < a.size(); ++i) {
            if (a[i] < b[i]) return -1;
            if (a[i] > b[i]) return 1;
        }
        return 0;
    }

    // 递增私钥
    static bool increment(std::vector<uint8_t>& key) {
        for (int i = key.size() - 1; i >= 0; --i) {
            if (++key[i] != 0)
                return true;
        }
        return false;  // 全部溢出，超出范围
    }

    // 检查是否在范围内
    bool isInRange(const std::vector<uint8_t>& key) const {
        return compare(key, start) >= 0 && compare(key, end) <= 0;
    }

    // 计算两个密钥之间的距离
    uint64_t calculate_distance(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) const {
        uint64_t distance = 0;
        for (size_t i = 0; i < a.size(); ++i) {
            distance = (distance << 8) | (b[i] - a[i]);
        }
        return distance;
    }

    // 添加偏移量到当前密钥
    void add_offset(std::vector<uint8_t>& key, uint64_t offset) {
        uint64_t carry = 0;
        for (int i = key.size() - 1; i >= 0 && (offset > 0 || carry > 0); --i) {
            uint64_t sum = key[i] + (offset & 0xFF) + carry;
            key[i] = sum & 0xFF;
            carry = sum >> 8;
            offset >>= 8;
        }
    }

public:
    // 构造函数：从十六进制字符串解析范围，支持起始百分比
    PrivateKeyRange(const std::string& rangeStr, double start_pct = 0.0) 
        : start_percent(start_pct), searched_keys(0) {
        
        // 解析范围字符串
        size_t colonPos = rangeStr.find(':');
        if (colonPos == std::string::npos)
            throw std::invalid_argument("Invalid range format, expected start:end");
            
        std::string startStr = rangeStr.substr(0, colonPos);
        std::string endStr = rangeStr.substr(colonPos + 1);
        
        // 移除0x前缀
        if (startStr.substr(0, 2) == "0x") startStr = startStr.substr(2);
        if (endStr.substr(0, 2) == "0x") endStr = endStr.substr(2);
        
        // 转换为字节数组
        start = hexToBytes(startStr);
        end = hexToBytes(endStr);
        
        // 确保长度一致，高位补0
        size_t maxLen = std::max(start.size(), end.size());
        start.insert(start.begin(), maxLen - start.size(), 0);
        end.insert(end.begin(), maxLen - end.size(), 0);
        current = start;
        
        // 验证范围有效性
        if (compare(start, end) >= 0)
            throw std::invalid_argument("Start range must be less than end range");
        
        // 计算总密钥数
        total_keys = calculate_distance(start, end) + 1;
        
        // 设置起始位置（根据百分比）
        if (start_pct > 0) {
            uint64_t offset = static_cast<uint64_t>((total_keys * start_pct) / 100.0);
            add_offset(current, offset);
        }
    }

    // 生成一个有效的私钥（连续递增）
    bool generateNext(std::vector<uint8_t>& key) {
        if (!isInRange(current)) return false;
        
        key = current;
        bool success = increment(current);
        searched_keys++;
        return success;
    }

    // 批量生成私钥（连续递增）
    void generateBatch(std::vector<std::vector<uint8_t>>& batch, size_t count) {
        batch.clear();
        batch.reserve(count);
        
        for (size_t i = 0; i < count; ++i) {
            std::vector<uint8_t> key;
            if (!generateNext(key)) break;
            
            if (isValidPrivateKey(key)) {
                batch.push_back(key);
            } else {
                increment(current);
                i--;
            }
        }
    }

    // 获取当前进度百分比
    double get_progress() const {
        return start_percent + (searched_keys * 100.0 / total_keys);
    }

    // 获取下次开始的百分比
    double get_next_start_percent() const {
        return get_progress();
    }

    // 十六进制转字节数组（静态方法）
    static std::vector<uint8_t> hexToBytes(const std::string& hexStr) {
        std::vector<uint8_t> bytes;
        bytes.reserve(hexStr.length() / 2);
        
        for (size_t i = 0; i < hexStr.length(); i += 2) {
            std::string byteStr = hexStr.substr(i, 2);
            bytes.push_back(static_cast<uint8_t>(std::stoi(byteStr, nullptr, 16)));
        }
        return bytes;
    }

    // 验证私钥有效性（静态方法）
static bool isValidPrivateKey(const std::vector<uint8_t>& key) {
    if (key.size() != 32) return false;
    static const uint8_t maxPrivkey[32] = {
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
        0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,
        0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41
    };
    return !(std::all_of(key.begin(), key.end(), [](uint8_t b) { return b == 0; }) ||
             std::memcmp(key.data(), maxPrivkey, 32) > 0);
    }


};

// 信号处理
void signal_handler(int signum) {
    global_state.running = false;
    std::cout << "\nThread " << std::this_thread::get_id() << " received signal " << signum 
              << ", initiating shutdown...\n";
}

// 私钥转公钥
bool private_to_public(const uint8_t* private_key, uint8_t* public_key, bool compressed = false) {
    if (!PrivateKeyRange::isValidPrivateKey(std::vector<uint8_t>(private_key, private_key + 32)))
        return false;

    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!ctx) return false;

    secp256k1_pubkey pubkey;
    int ret = secp256k1_ec_pubkey_create(ctx, &pubkey, private_key);

    if (ret) {
        size_t pubkey_len = compressed ? 33 : 65;
        secp256k1_ec_pubkey_serialize(ctx, public_key, &pubkey_len, &pubkey, 
                                    compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED);
    }

    secp256k1_context_destroy(ctx);
    return ret != 0;
}

// 优化的私钥转公钥
std::vector<uint8_t> private_to_public_avx2(const std::vector<uint8_t>& private_key, bool compressed = false) {
    std::vector<uint8_t> public_key(compressed ? 33 : 65);
    if (!private_to_public(private_key.data(), public_key.data(), compressed)) {
        throw std::runtime_error("Invalid private key or failed to generate public key");
    }
    return public_key;
}

// 比特币地址生成
std::string public_to_bitcoin(const std::vector<uint8_t>& public_key, bool compressed = false) {
    std::vector<uint8_t> pubkey_to_hash;
    
    if (compressed && (public_key[0] == 0x02 || public_key[0] == 0x03)) {
        pubkey_to_hash.assign(public_key.begin(), public_key.end());
    } 
    else if (public_key[0] == 0x04) {
        pubkey_to_hash.resize(33);
        pubkey_to_hash[0] = (public_key[64] & 1) ? 0x03 : 0x02;
        std::copy(public_key.begin() + 1, public_key.begin() + 33, pubkey_to_hash.begin() + 1);
    } else {
        throw std::invalid_argument("Invalid public key format");
    }

    std::vector<uint8_t> sha256_hash(32);
    SHA256(pubkey_to_hash.data(), pubkey_to_hash.size(), sha256_hash.data());

    // 使用 EVP 接口计算 RIPEMD160 哈希
    std::vector<uint8_t> ripemd_hash(20);
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }
    
    if (EVP_DigestInit_ex(mdctx, EVP_ripemd160(), NULL) != 1 ||
        EVP_DigestUpdate(mdctx, sha256_hash.data(), sha256_hash.size()) != 1 ||
        EVP_DigestFinal_ex(mdctx, ripemd_hash.data(), NULL) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("Failed to compute RIPEMD160 hash");
    }
    EVP_MD_CTX_free(mdctx);

    std::vector<char> encoded(50);
    size_t encoded_len = encoded.size();
    
    std::vector<uint8_t> checksum_input(21);
    checksum_input[0] = 0x00; // 比特币主网版本字节
    std::copy(ripemd_hash.begin(), ripemd_hash.end(), checksum_input.begin() + 1);
    
    std::vector<uint8_t> checksum(32);
    SHA256(checksum_input.data(), checksum_input.size(), checksum.data());
    SHA256(checksum.data(), checksum.size(), checksum.data());
    
    std::vector<uint8_t> payload(25);
    std::copy(checksum_input.begin(), checksum_input.end(), payload.begin());
    std::copy(checksum.begin(), checksum.begin() + 4, payload.begin() + 21);
    
    if (!b58enc(encoded.data(), &encoded_len, payload.data(), payload.size())) {
        throw std::runtime_error("Base58 encoding failed");
    }

    return std::string(encoded.data(), encoded_len - 1);
}

// 地址清理函数
std::string clean_address(const std::string& addr) {
    const std::string base58_chars = 
        "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    std::string cleaned;
    for (char c : addr) {
        if (base58_chars.find(c) != std::string::npos) {
            cleaned += c;
        }
    }
    return cleaned;
}

// 从文件加载目标地址
bool load_target_addresses(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "[ERROR] Failed to open target addresses file: " << filename << std::endl;
        return false;
    }

    std::string line;
    size_t inserted = 0;
    while (std::getline(file, line)) {
        // 使用 clean_address 函数统一清理逻辑
        std::string cleaned = clean_address(line);
        
        if (!cleaned.empty() && cleaned[0] == '1' && cleaned.size() >= 26 && cleaned.size() <= 35) {
            global_state.target_addresses.insert(cleaned);
            ++inserted;
        }
    }

    file.close();
    std::cout << "[INFO] Loaded " << inserted << " target addresses" << std::endl;
    return true;
}

// 内存对齐分配器
template <typename T, size_t Alignment = CACHE_LINE_SIZE>
using AlignedAllocator = std::allocator<T>;

// 定义Block结构体
struct Block {
    void* memory;
    size_t size;
    size_t used;
    Block* next;
};

// 改进的线程本地内存池
class ImprovedThreadLocalMemoryPool {
private:
    struct LargeAllocation {
        void* ptr;
        size_t size;
        LargeAllocation* next;
    };
    
    Block* current_block;
    LargeAllocation* large_allocations;
    const size_t block_size;
    std::atomic<size_t> total_allocated{0};
    
public:
    explicit ImprovedThreadLocalMemoryPool(size_t size = MEMORY_POOL_BLOCK_SIZE)
        : block_size(size), large_allocations(nullptr) {
        current_block = allocate_block();
    }
    
    ~ImprovedThreadLocalMemoryPool() {
        cleanup_large_allocations();
        
        while (current_block) {
            Block* next = current_block->next;
            sodium_memzero(current_block->memory, current_block->size);
            free(current_block->memory);
            current_block = next;
        }
    }

                void* allocate(size_t size) {
                size_t aligned_size = (size >= 64 || size % 64 == 0) ? size : ((size / 64) + 1) * 64;

                if (aligned_size > block_size / 2) {
                    void* ptr = aligned_alloc(64, aligned_size);
                    if (!ptr) throw std::bad_alloc();

                    total_allocated.fetch_add(aligned_size);

                    LargeAllocation* alloc = static_cast<LargeAllocation*>(malloc(sizeof(LargeAllocation)));
                    if (!alloc) {
                        free(ptr);
                        throw std::bad_alloc();
                    }
                    *alloc = {ptr, aligned_size, large_allocations};
                    large_allocations = alloc;
                    return ptr;
                }

                Block* suitable_block = nullptr;
                Block* block = current_block;
                while (block) {
                    if (block->used + aligned_size <= block->size) {
                        suitable_block = block;
                        break;
                    }
                    block = block->next;
                }

                if (suitable_block) {
                    void* ptr = static_cast<char*>(suitable_block->memory) + suitable_block->used;
                    suitable_block->used += aligned_size;
                    total_allocated.fetch_add(aligned_size);
                    return ptr;
                }

                Block* new_block = allocate_block();
                if (!new_block) throw std::bad_alloc();

                new_block->used = aligned_size;
                new_block->next = current_block;
                current_block = new_block;
                total_allocated.fetch_add(aligned_size);
                
                return static_cast<char*>(new_block->memory);
            }

            void periodic_cleanup() {
                cleanup_large_allocations();
            }

            void cleanup_large_allocations() {
                LargeAllocation* current = large_allocations;
                while (current) {
                    LargeAllocation* next = current->next;
                    sodium_memzero(current->ptr, current->size);
                    free(current->ptr);
                    total_allocated.fetch_sub(current->size);
                    free(current);
                    current = next;
                }
                large_allocations = nullptr;
            }

            size_t get_allocated_size() const {
                return total_allocated.load();
            }

        private:
            Block* allocate_block() {
                void* memory = malloc(block_size);
                if (!memory) throw std::bad_alloc();

                Block* block = static_cast<Block*>(malloc(sizeof(Block)));
                if (!block) {
                    free(memory);
                    throw std::bad_alloc();
                }

                block->memory = memory;
                block->size = block_size;
                block->used = 0;
                block->next = nullptr;
                
                return block;
            }
        };
        // 辅助函数：字节数组转十六进制字符串
        std::string bytesToHex(const std::vector<uint8_t>& bytes);

        // 辅助函数：字节数组转十六进制字符串
        std::string bytesToHex(const std::vector<uint8_t>& bytes) {
            std::stringstream ss;
            ss << std::hex << std::setfill('0');
            for (uint8_t b : bytes) {
                ss << std::setw(2) << (int)b;
            }
            return ss.str();
        }
        double last_progress = 0.0;

    bool parse_wif_private_key(const std::string& wif_private_key, std::vector<uint8_t>& private_key, bool& compressed) {
    try {
        // 1. Base58解码WIF私钥
        uint8_t decoded[100] = {0};
        size_t decoded_len = sizeof(decoded);
        
        if (!b58tobin(decoded, &decoded_len, wif_private_key.c_str(), wif_private_key.length())) {
            std::cerr << "Base58 decoding failed\n";
            return false;
        }
        
        // 调整数据位置(Base58解码可能会在前面留下空字节)
        const uint8_t* payload = decoded + (sizeof(decoded) - decoded_len);
        
        // 2. 验证WIF结构
        if (decoded_len != 37 && decoded_len != 38) {
            std::cerr << "Invalid WIF length: " << decoded_len << " bytes (expected 37 or 38)\n";
            return false;
        }
        
        if (payload[0] != 0x80) {
            std::cerr << "Invalid WIF version byte: 0x" << std::hex << (int)payload[0] 
                     << " (expected 0x80)\n";
            return false;
        }
        
        // 3. 检查压缩标志
        compressed = false;
        size_t privkey_len = 32;
        
        if (decoded_len == 38) {
            if (payload[33] == 0x01) {
                compressed = true;
            } else {
                std::cerr << "Invalid compression flag: 0x" << std::hex << (int)payload[33] 
                         << " (expected 0x01 if present)\n";
                return false;
            }
        }
        
        // 4. 验证校验和
        size_t data_len = decoded_len - 4;
        std::vector<uint8_t> checksum = compute_checksum(payload, data_len);
        
        if (!std::equal(checksum.begin(), checksum.end(), payload + data_len)) {
            std::cerr << "Checksum verification failed\n";
            return false;
        }
        
        // 5. 提取私钥
        private_key.assign(payload + 1, payload + 1 + privkey_len);
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error parsing WIF private key: " << e.what() << "\n";
        return false;
    }
}
//比特币生产者线程
void bitcoin_producer_thread(LockFreeQueue<std::shared_ptr<ImprovedBatchTask>>& task_queue, double start_percent = 0.0) {
    std::unique_ptr<PrivateKeyRange> key_range;
    try {
        std::string start_hex = bytesToHex(btc_config.start_range);
        std::string end_hex = bytesToHex(btc_config.end_range);
        std::string range_str = start_hex + ":" + end_hex;

        key_range = std::make_unique<PrivateKeyRange>(range_str, start_percent);
    } catch (const std::exception& e) {
        std::cerr << "Error creating private key range: " << e.what() << std::endl;
        global_state.running = false;
        return;
    }

    ImprovedThreadLocalMemoryPool memory_pool;
    std::thread cleanup_thread([&memory_pool]() {
        while (global_state.running) {
            std::this_thread::sleep_for(std::chrono::seconds(30));
            memory_pool.periodic_cleanup();
        }
    });

    double last_progress = key_range->get_progress();

    while (global_state.running) {
        // 背压控制器：主动delay
        int delay = g_backpressure_controller->getDelayMs();
        if (delay > 0) std::this_thread::sleep_for(std::chrono::milliseconds(delay));

        if (g_backpressure_controller->getState() == BackpressureState::STOP_PRODUCTION) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }

        auto batch = std::make_shared<ImprovedBatchTask>();
        std::vector<std::vector<uint8_t>> raw_private_keys;
        key_range->generateBatch(raw_private_keys, BATCH_SIZE);
        batch->private_keys = std::move(raw_private_keys);

        if (batch->private_keys.empty()) {
            global_state.running = false;
            std::cout << "\n[INFO] Reached end of key range. Stopping production." << std::endl;

            // 发送结束标志（nullptr）通知所有消费者退出
            for (int i = 0; i < CONSUMER_THREADS; ++i) {
                task_queue.enqueue(nullptr);
            }
            break;
        }

        task_queue.enqueue(batch);

        // 安全更新计数器，线程安全用原子
        global_state.keys_generated.fetch_add(batch->private_keys.size(), std::memory_order_relaxed);

        double current_progress = key_range->get_progress();
        if (current_progress - last_progress >= 5.0) {
            std::cout << "\r[PROGRESS] " << std::fixed << std::setprecision(2)
                      << current_progress << "% completed" << std::flush;
            last_progress = current_progress;
        }

        g_backpressure_controller->updateStats(task_queue.size());
    }

    if (cleanup_thread.joinable()) {
        cleanup_thread.join();
    }

    double next_start = key_range->get_next_start_percent();
    std::cout << "\n[Next Start] Continue from: " << std::fixed << std::setprecision(2)
              << next_start << "%\n";
}

// 比特币消费者线程
void bitcoin_consumer_thread(LockFreeQueue<std::shared_ptr<ImprovedBatchTask>>& task_queue) {
    while (true) {
        std::shared_ptr<ImprovedBatchTask> batch;
        task_queue.dequeue(batch);

        // 收到退出信号，batch == nullptr
        if (!batch) break;

        batch->addresses.resize(batch->private_keys.size());

        for (size_t i = 0; i < batch->private_keys.size(); ++i) {
            try {
                std::vector<uint8_t> private_key = batch->private_keys[i];
                bool compressed = btc_config.use_compressed;

                auto public_key = private_to_public_avx2(private_key, compressed);
                batch->addresses[i] = public_to_bitcoin(public_key, compressed);

                std::string cleaned_address = clean_address(batch->addresses[i]);

                global_state.addresses_checked.fetch_add(1, std::memory_order_relaxed);

                if (global_state.target_addresses.count(cleaned_address) > 0) {
                    std::lock_guard<std::mutex> lock(global_state.file_mutex);
                    std::ofstream out(btc_config.result_file, std::ios::app);
                    if (out) {
                        out << "Match found!\nPrivate Key: ";
                        for (auto b : private_key) {
                            out << std::hex << std::setw(2) << std::setfill('0') << (int)b;
                        }
                        out << "\nAddress: " << cleaned_address << "\n\n";
                    }
                    global_state.matches_found.fetch_add(1, std::memory_order_relaxed);
                }
            } catch (...) {
                // 错误处理
            }
        }
    }
}


        // 比特币监控线程
        void bitcoin_monitor_thread() {
            auto start_time = std::chrono::steady_clock::now();
            uint64_t last_count = 0;
            
            while (global_state.running) {
                std::this_thread::sleep_for(std::chrono::seconds(120));
                
                auto now = std::chrono::steady_clock::now();
                auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - start_time);
                uint64_t total = global_state.addresses_checked.load();
                uint64_t delta = total - last_count;
                
                std::cout << "\r[Bps] "
                          << "S: " << delta/120 << " keys/s | "
                          << "T: " << total << " | ";
                
                // 显示范围信息
                std::cout << "Range: 0x" << bytesToHex(btc_config.start_range)
                          << " - 0x" << bytesToHex(btc_config.end_range);
                
                std::cout << std::dec << " | "
                          << "Elapsed: " << elapsed.count()/3600 << "h "
                          << (elapsed.count()%3600)/60 << "m "
                          << (elapsed.count()%60) << "s";
                
                last_count = total;
            }
        }

        // SHA-256安全封装
        bool my_sha256(void* digest, const void* data, size_t len) {
            if (!digest || !data || len == 0) return false;
            return SHA256(static_cast<const unsigned char*>(data), len, static_cast<unsigned char*>(digest)) != nullptr;
        }

        // OpenSSL清理
        void cleanup_openssl() {
        #if OPENSSL_VERSION_NUMBER < 0x10100000L
            EVP_cleanup();
            ERR_free_strings();
            CRYPTO_cleanup_all_ex_data();
            CONF_modules_unload(1);
            CONF_modules_free();
            ENGINE_cleanup();
        #else
            // OpenSSL 1.1.0+ 会自动清理
        #endif
        }

        // 解析十六进制范围
        bool parse_hex_range(const std::string& range_str, std::vector<uint8_t>& start, std::vector<uint8_t>& end) {
            size_t colon_pos = range_str.find(':');
            if (colon_pos == std::string::npos) return false;
            
            try {
                std::string start_str = range_str.substr(0, colon_pos);
                std::string end_str = range_str.substr(colon_pos + 1);
                
                // 移除"0x"前缀
                if (start_str.substr(0, 2) == "0x") start_str = start_str.substr(2);
                if (end_str.substr(0, 2) == "0x") end_str = end_str.substr(2);
                
                // 确保长度为偶数
                if (start_str.length() % 2 != 0) start_str = "0" + start_str;
                if (end_str.length() % 2 != 0) end_str = "0" + end_str;
                
                // 转换为字节数组
                start = PrivateKeyRange::hexToBytes(start_str);
                end = PrivateKeyRange::hexToBytes(end_str);
                
                // 确保长度一致，高位补0
                size_t max_len = std::max(start.size(), end.size());
                start.insert(start.begin(), max_len - start.size(), 0);
                end.insert(end.begin(), max_len - end.size(), 0);
                
                // 检查范围有效性
                for (size_t i = 0; i < start.size(); ++i) {
                    if (start[i] < end[i]) break;
                    if (start[i] > end[i]) return false;
                }
                
                return true;
            } catch (...) {
                return false;
            }
        }

int main(int argc, char* argv[]) {
    AdaptiveBackpressure backpressure(MAX_QUEUE_SIZE);
    g_backpressure_controller = &backpressure;

    b58_sha256_impl = my_sha256;
    if (!b58_sha256_impl) {
        std::cerr << "Error: SHA256 implementation not set for Base58!" << std::endl;
        return 1;
    }

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    
    if (sodium_init() < 0) {
        std::cerr << "Failed to initialize libsodium" << std::endl;
        return 1;
    }
    
    secp256k1_context* secp_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!secp_ctx) {
        std::cerr << "Failed to initialize secp256k1" << std::endl;
        return 1;
    }
    secp256k1_context_destroy(secp_ctx);

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    std::cout << "[INFO] CPU Cores detected: " << HARDWARE_THREADS << std::endl;
    std::cout << "[INFO] Thread configuration: Producers=" << PRODUCER_THREADS 
              << ", Consumers=" << CONSUMER_THREADS 
              << ", Monitors=" << MONITOR_THREADS << std::endl;

    // 初始化比特币配置
    btc_config.use_compressed = true;
    btc_config.target_file = "targets.txt";  // 默认目标文件
    btc_config.result_file = "bitcoin_puzzle_result.txt";
    btc_config.use_custom_range = false;
    btc_config.is_256bit_range = false;
    
    // 解析命令行参数
    double start_percent = 0.0;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        // 新增命令行参数支持起始百分比
        if (arg == "-s" && i + 1 < argc) {
            start_percent = std::stod(argv[++i]);
            std::cout << "[CONFIG] Starting from: " << start_percent << "%\n";
        }
        if (arg == "-r" && i + 1 < argc) {
            std::string range_str = argv[++i];
            
            // 解析范围
            if (!parse_hex_range(range_str, btc_config.start_range, btc_config.end_range)) {
                std::cerr << "Error: Invalid range format. Use hex format: start:end\n"
                          << "Example: 0x800000000000000000:0xffffffffffffffffff" << std::endl;
                return 1;
            }
            
            btc_config.use_custom_range = true;
            btc_config.is_256bit_range = (btc_config.start_range.size() == 32 && btc_config.end_range.size() == 32);
            
            std::cout << "[INFO] Using custom range mode: 0x" << bytesToHex(btc_config.start_range)
                      << " - 0x" << bytesToHex(btc_config.end_range) << std::endl;
        }
        else if (arg == "-f" && i + 1 < argc) {
            btc_config.target_file = argv[++i];
            std::cout << "[INFO] Target addresses file: " << btc_config.target_file << std::endl;
        }
        else if (arg == "-a" && i + 1 < argc) {
            std::string target_addr = clean_address(argv[++i]);
            if (!target_addr.empty()) {
                global_state.target_addresses.insert(target_addr);
                std::cout << "[INFO] Target address: " << target_addr << std::endl;
            } else {
                std::cerr << "Error: Invalid target address provided" << std::endl;
                return 1;
            }
        } 
        else if (arg == "-u") {
            btc_config.use_compressed = false;
            std::cout << "[INFO] Using uncompressed public keys" << std::endl;
        } 
        else if (arg == "-o" && i + 1 < argc) {
            btc_config.result_file = argv[++i];
            std::cout << "[INFO] Result file: " << btc_config.result_file << std::endl;
        }
        else if (arg == "-h" || arg == "--help") {
            std::cout << "BPS:\n"
                      << "  -r <range>      Use direct hex range (e.g. 0x800000000000000000:0xffffffffffffffffff)\n"
                      << "  -f <file>       File containing target Bitcoin addresses (one per line)\n"
                      << "  -a <address>    Single target Bitcoin address to find\n"
                      << "  -u              Use uncompressed public keys\n"
                      << "  -o <file>       Output file for results\n"
                      << "  -h, --help      Show this help message\n";
            return 0;
        }
    }
    
    // 加载目标地址文件（如果指定）
    if (!btc_config.target_file.empty() && global_state.target_addresses.empty()) {
        if (!load_target_addresses(btc_config.target_file)) {
            std::cerr << "Error: Failed to load target addresses from file" << std::endl;
            return 1;
        }
    }
    
    // 检查是否有目标地址
    if (global_state.target_addresses.empty()) {
        std::cerr << "Error: No target addresses specified. Use -a or -f option\n";
        return 1;
    }
    
    // 如果未指定范围，使用默认范围
    if (!btc_config.use_custom_range) {
        std::cout << "[INFO] No range specified. Using default range: 0x800000000000000000:0xffffffffffffffffff" << std::endl;
        btc_config.start_range = PrivateKeyRange::hexToBytes("800000000000000000");
        btc_config.end_range = PrivateKeyRange::hexToBytes("ffffffffffffffffff");
        btc_config.use_custom_range = true;
    }
    
    // 计算并显示搜索范围大小
    uint64_t estimated_keys = 0;
    if (btc_config.is_256bit_range) {
        // 256位范围（简化计算）
        estimated_keys = UINT64_MAX; 
    } else {
        // 计算实际范围大小
        estimated_keys = 0;
        for (size_t i = 0; i < btc_config.end_range.size(); ++i) {
            uint64_t diff = btc_config.end_range[i] - btc_config.start_range[i];
            estimated_keys = (estimated_keys << 8) | diff;
        }
        estimated_keys += 1;  // 包含结束值
    }
    
    double range_size_gb = static_cast<double>(estimated_keys) / (1ULL << 30);
    std::cout << "[INFO] Searching approximately " << std::fixed << std::setprecision(2) << range_size_gb 
              << " billion possible keys (" << estimated_keys << " total)" << std::endl;
    std::cout << "[INFO] Searching for " << global_state.target_addresses.size() << " target addresses" << std::endl;
    
    // 初始化全局状态
    global_state.result_file = btc_config.result_file;
    
    // 创建监控队列
    LockFreeQueue<std::shared_ptr<ImprovedBatchTask>> task_queue(16384);

    // 创建并启动线程
    std::vector<std::thread> producer_threads;
    for (size_t i = 0; i < PRODUCER_THREADS; ++i) {
        producer_threads.emplace_back(bitcoin_producer_thread, std::ref(task_queue), start_percent);
    }

    std::vector<std::thread> consumer_threads;
    std::vector<std::thread> monitor_threads;

    // 启动背压监控线程
    monitor_threads.emplace_back([&backpressure]() {
        while (global_state.running) {
            std::this_thread::sleep_for(std::chrono::seconds(180));
            backpressure.logStatus();
        }
    });
    
    
    // 启动比特币消费者线程
    for (size_t i = 0; i < CONSUMER_THREADS; ++i) {
        consumer_threads.emplace_back(bitcoin_consumer_thread, std::ref(task_queue));
    }
    
    // 创建比特币监控线程
    monitor_threads.emplace_back(bitcoin_monitor_thread);
    
    std::cout << "[INFO] All threads started. Total: " 
              << producer_threads.size() + consumer_threads.size() + monitor_threads.size()
              << " threads" << std::endl;
    
    std::cout << "[INFO] Using " << (btc_config.use_compressed ? "compressed" : "uncompressed") 
              << " public keys" << std::endl;
    std::cout << "[INFO] Output file: " << btc_config.result_file << std::endl;
    std::cout << "[INFO] Memory pool size: " << MEMORY_POOL_MAX_SIZE / (1024*1024) << " MB" << std::endl;

    // *** 等待生产者线程结束
    for (auto& t : producer_threads) {
        if (t.joinable()) {
            t.join();
        }
    }
    std::cout << "\n[INFO] All producer threads have exited" << std::endl;

    // *** 给消费者线程发送退出信号（nullptr）
    for (size_t i = 0; i < consumer_threads.size(); ++i) {
        while (!task_queue.enqueue(nullptr)) {
            std::this_thread::yield();
        }
    }

    size_t remaining_tasks = 0;
    while (!task_queue.empty()) {
        std::shared_ptr<ImprovedBatchTask> batch;
        if (task_queue.dequeue(batch)) {
            for (auto& key : batch->private_keys) {
                sodium_memzero(key.data(), key.size());
            }
            remaining_tasks++;
        }
    }
    if (remaining_tasks > 0) {
        std::cout << "[INFO] Cleared " << remaining_tasks << " remaining tasks in queue" << std::endl;
    }

    // *** 等待消费者线程退出
    for (auto& t : consumer_threads) {
        if (t.joinable()) {
            t.join();
        }
    }
    std::cout << "[INFO] All consumer threads have exited" << std::endl;

    // 停止运行，通知监控线程退出
    global_state.running = false;

    // 等待监控线程退出
    for (auto& t : monitor_threads) {
        if (t.joinable()) {
            t.join();
        }
    }
    std::cout << "[INFO] All monitor threads have exited" << std::endl;

    std::cout << "[INFO] Program terminated gracefully." << std::endl;
    return 0;
}
