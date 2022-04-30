#include <fastcap/ring_buffer.hpp>

size_t RingBuffer::offset_add(size_t pos, size_t offset) const noexcept {
    const auto cap = cap_;
    pos += offset;
    return pos - (cap * static_cast<size_t>(pos >= cap));
}

size_t RingBuffer::decrement(size_t pos) const noexcept {
    const auto cond = static_cast<size_t>(pos == 0);
    const auto not_cond = cond ^ 1;
    return ((pos - 1) * not_cond) | ((cap_ - 1) * cond);
}

size_t RingBuffer::distance(size_t start, size_t end) const noexcept {
    const auto cond = static_cast<size_t>(end < start);
    const auto not_cond = cond ^ 1;
    return ((end - start) * not_cond) | ((cap_ - end + start) * cond);
}

void RingBuffer::write_impl(size_t pos, const void* buf, size_t len) {
    const auto cap = cap_;
    if (pos + len > cap) {
        const auto first_len = cap - pos;
        const auto second_len = len - first_len;
        std::memcpy(mem_ + pos, buf, first_len);
        std::memcpy(mem_, reinterpret_cast<const uint8_t*>(buf) + first_len, second_len);
    } else {
        std::memcpy(mem_ + pos, buf, len);
    }
}

void RingBuffer::read_impl(size_t pos, void* buf, size_t len) {
    const auto cap = cap_;
    if (pos + len > cap) {
        const auto first_len = cap - pos;
        const auto second_len = len - first_len;
        std::memcpy(buf, mem_ + pos, first_len);
        std::memcpy(reinterpret_cast<uint8_t*>(buf) + first_len, mem_, second_len);
    } else {
        std::memcpy(buf, mem_ + pos, len);
    }
}

RingBuffer::RingBuffer(size_t capacity)
    : mem_(new uint8_t[capacity]),
      cap_(capacity),
      free_end_(capacity - 1) {}

RingBuffer::~RingBuffer() {
    delete[] mem_;
}

void RingBuffer::notify_one_consumer() {
    if (mut_.try_lock()) {
        mut_.unlock();
    }
    cv_.notify_one();
}

void RingBuffer::notify_all_consumers() {
    if (mut_.try_lock()) {
        mut_.unlock();
    }
    cv_.notify_all();
}

bool RingBuffer::prepare_write(size_t num_bytes) {
    auto needed_bytes = num_bytes + sizeof(size_t);
    auto end = end_.load(std::memory_order_relaxed);
    auto free_end = free_end_.load(std::memory_order_relaxed);
    auto free_len = distance(end, free_end);
    if (needed_bytes > free_len) {
        return false;
    }

    write_impl(end, &num_bytes, sizeof(size_t));
    write_pos_ = offset_add(end, sizeof(size_t));
    write_end_ = offset_add(write_pos_, num_bytes);
    return true;
}

void RingBuffer::write_some(const void* buf, size_t len) {
    write_impl(write_pos_, buf, len);
    write_pos_ = offset_add(write_pos_, len);
}

void RingBuffer::commit_write() {
    end_.store(write_end_);
    notify_one_consumer();
}

bool RingBuffer::try_read(std::vector<uint8_t>& buf) {
    std::ptrdiff_t tmp_begin = -1;
    while ((tmp_begin = begin_.exchange(-1, std::memory_order_relaxed)) < 0);
    size_t begin = static_cast<size_t>(tmp_begin);
    if (begin == end_.load(std::memory_order_relaxed)) {
        begin_.store(tmp_begin, std::memory_order_relaxed);
        notify_one_consumer();
        return false;
    }

    size_t len = 0;
    read_impl(begin, &len, sizeof(size_t));
    auto new_begin = offset_add(begin, len + sizeof(size_t));
    begin_.store(static_cast<std::ptrdiff_t>(new_begin), std::memory_order_relaxed);
    notify_one_consumer();
    buf.resize(len);
    read_impl(offset_add(begin, sizeof(size_t)), buf.data(), len);
    size_t new_end = decrement(new_begin);
    size_t expected_end = decrement(begin);
    size_t tmp_end = expected_end;
    while (!free_end_.compare_exchange_strong(tmp_end, new_end)) {
        tmp_end = expected_end;
    }
    return true;
}

void RingBuffer::read(std::vector<uint8_t>& buf) {
    try_read_do_while([] { return true; }, buf);
}
