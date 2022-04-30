#ifndef FASTCAP_RING_BUFFER_HPP
#define FASTCAP_RING_BUFFER_HPP

#include <atomic>
#include <mutex>
#include <condition_variable>
#include <cstdint>
#include <vector>
#include <cstring>

// single producer, multiple consumer
class RingBuffer {
  private:
    uint8_t* mem_{nullptr};
    const size_t cap_{0};
    std::atomic<std::ptrdiff_t> begin_{0};
    std::atomic<size_t> end_{0};
    std::atomic<size_t> free_end_{0};
    size_t write_pos_{0};
    size_t write_end_{0};
    std::mutex mut_;
    std::condition_variable cv_;

    size_t offset_add(size_t pos, size_t offset) const noexcept;
    size_t decrement(size_t pos) const noexcept;
    size_t distance(size_t start, size_t end) const noexcept;
    void write_impl(size_t pos, const void* buf, size_t len);
    void read_impl(size_t pos, void* buf, size_t len);

  public:
    explicit RingBuffer(size_t capacity);
    RingBuffer(const RingBuffer&) = delete;
    RingBuffer(RingBuffer&&) = delete;
    ~RingBuffer();
    RingBuffer& operator=(const RingBuffer&) = delete;
    RingBuffer& operator=(RingBuffer&&) = delete;

    void notify_one_consumer();
    void notify_all_consumers();

    bool prepare_write(size_t num_bytes);
    void write_some(const void* buf, size_t len);
    void commit_write();

    bool try_read(std::vector<uint8_t>& buf);
    void read(std::vector<uint8_t>& buf);

    template <typename Pred>
    bool try_read_do_while(Pred pred, std::vector<uint8_t>& buf) {
        bool flag = true;
        while (!try_read(buf)) {
            {
                std::unique_lock<std::mutex> lock{mut_};
                cv_.wait(lock, [this, &flag, &pred] {
                    auto begin = begin_.load(std::memory_order_relaxed);
                    auto end = static_cast<std::ptrdiff_t>(end_.load(std::memory_order_relaxed));
                    return !(flag = pred()) || (begin >= 0 && begin != end);
                });
            }
            if (!flag) {
                return false;
            }
        }
        return true;
    }

    template <typename Pred>
    bool try_read_while(Pred&& pred, std::vector<uint8_t>& buf) {
        if (!pred()) { return false; }
        return try_read_do_while(std::forward<Pred>(pred), buf);
    }
};

#endif
