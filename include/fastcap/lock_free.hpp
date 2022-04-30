#ifndef FASTCAP_LOCK_FREE_HPP
#define FASTCAP_LOCK_FREE_HPP

#include <atomic>
#include <cstdlib>
#include <type_traits>
#include <condition_variable>
#include <mutex>
#include <optional>
#include <vector>

#include <spdlog/spdlog.h>

template <typename T>
class LFData {
  private:
    union data_t {
        T data;

        data_t() {}
        data_t(const data_t&) {}
        data_t(data_t&&) {}
        ~data_t() {}
        data_t& operator=(const data_t&) { return *this; }
        data_t& operator=(data_t&&) { return *this; }
    };

    data_t data_;
    std::atomic<char> flag_{0};

    static constexpr bool NEEDS_DESTRUCT = !std::is_trivially_destructible_v<T>;

  public:
    LFData() = default;

    LFData(const LFData&) {
        spdlog::critical("lock-free data should never be copied");
        std::exit(1);
    }

    LFData(LFData&&) {
        spdlog::critical("lock-free data should never be moved");
        std::exit(1);
    }

    ~LFData() {
        if constexpr (NEEDS_DESTRUCT) {
            if (flag_.load() > 0) {
                data_.data.~T();
            }
        }
    }

    LFData& operator=(const LFData&) {
        spdlog::critical("lock-free data should never be copied");
        std::exit(1);
        return *this;
    }

    LFData& operator=(LFData&&) {
        spdlog::critical("lock-free data should never be moved");
        std::exit(1);
        return *this;
    }

    template <typename... Args>
    void set(Args&&... args) {
        if constexpr (NEEDS_DESTRUCT) {
            char flag = 0;
            while ((flag = flag_.exchange(-1)) < 0);
            if (flag > 0) {
                data_.data.~T();
            }
        } else {
            while (flag_.exchange(-1) < 0);
        }
        new(&data_.data) T(std::forward<Args>(args)...);
        flag_.store(1);
    }

    std::optional<T> take() {
        char flag = 0;
        std::optional<T> ret;
        while ((flag = flag_.exchange(-1)) < 0);
        if (flag > 0) {
            ret.emplace(std::move(data_.data));
            if constexpr (NEEDS_DESTRUCT) {
                data_.data.~T();
            }
        }
        flag_.store(0);
        return ret;
    }
};

template <typename T>
struct LFEntry {
    LFData<T> data;
    std::atomic<LFEntry*> next{nullptr};
};

template <typename T, template <typename> class Producer, template <typename> class Consumer>
class LFQueue : public Producer<T>, public Consumer<T> {
  private:
    std::vector<LFEntry<T>> alloc_;

  public:
    using value_type = T;

    LFQueue(size_t capacity) : alloc_(capacity + 2) {
        for (auto& entry : alloc_) {
            entry.next.store(&entry + 1, std::memory_order_relaxed);
        }
        auto head = &alloc_.back();
        auto tail = head;
        auto free_head = &alloc_.front();
        auto free_tail = head - 1;

        tail->next.store(nullptr, std::memory_order_relaxed);
        free_tail->next.store(nullptr, std::memory_order_relaxed);

        this->producer_init(free_head, tail);
        this->consumer_init(head, free_tail);
    }

    size_t capacity() const noexcept {
        return alloc_.size() - 2;
    }
};

template <typename T>
class SingleProducer {
  private:
    LFEntry<T>* free_head_{nullptr};
    LFEntry<T>* tail_{nullptr};

    void producer_init(LFEntry<T>* free_head, LFEntry<T>* tail) {
        free_head_ = free_head;
        tail_ = tail;
    }

    template <typename U, template <typename> class Producer, template <typename> class Consumer>
    friend class LFQueue;

    LFEntry<T>* new_entry() {
        auto head = free_head_;
        auto next = head->next.exchange(nullptr, std::memory_order_relaxed);
        if (next == nullptr) {
            return nullptr;
        }
        free_head_ = next;
        return head;
    }

  public:
    template <typename... Args>
    std::optional<T> try_push(Args&&... args) {
        auto entry = new_entry();
        if (entry == nullptr) {
            return std::optional<T>{std::in_place, std::forward<Args>(args)...};
        }
        entry->data.set(std::forward<Args>(args)...);
        entry->next.store(tail_, std::memory_order_relaxed);
        tail_ = entry;
        return std::nullopt;
    }
};

template <typename T>
class SingleConsumer {
  private:
    LFEntry<T>* free_tail_{nullptr};
    LFEntry<T>* head_{nullptr};

    void consumer_init(LFEntry<T>* head, LFEntry<T>* free_tail) {
        free_tail_ = free_tail;
        head_ = head;
    }

    template <typename U, template <typename> class Producer, template <typename> class Consumer>
    friend class LFQueue;

    void del_entry(LFEntry<T>* entry) {
        entry->next.store(free_tail_, std::memory_order_relaxed);
        free_tail_ = entry;
    }

  public:
    std::optional<T> try_pop() {
        auto head = head_;
        auto ret = head->data.take();
        if (ret.has_value()) {
            auto next = head->next.exchange(nullptr, std::memory_order_relaxed);
            if (next != nullptr) {
                head_ = next;
                del_entry(head);
            }
        }
        return ret;
    }
};

template <typename T>
class MultipleProducer {
  private:
    std::atomic<LFEntry<T>*> free_head_{nullptr};
    std::atomic<LFEntry<T>*> tail_{nullptr};

    void producer_init(LFEntry<T>* free_head, LFEntry<T>* tail) {
        free_head_.store(free_head, std::memory_order_relaxed);
        tail_.store(tail, std::memory_order_relaxed);
    }

    template <typename U, template <typename> class Producer, template <typename> class Consumer>
    friend class LFQueue;

    LFEntry<T>* new_entry() {
        auto head = free_head_.load(std::memory_order_relaxed);
        for (;;) {
            auto next = head->next.load(std::memory_order_relaxed);
            if (next == nullptr) {
                return nullptr;
            }
            if (free_head_.compare_exchange_strong(head, next, std::memory_order_relaxed)) {
                break;
            }
        }
        head->next.store(nullptr, std::memory_order_relaxed);
        return head;
    }

  public:
    template <typename... Args>
    std::optional<T> try_push(Args&&... args) {
        auto entry = new_entry();
        if (entry == nullptr) {
            return std::optional<T>{std::in_place, std::forward<Args>(args)...};
        }
        entry->data.set(std::forward<Args>(args)...);
        auto tail = tail_.exchange(entry, std::memory_order_relaxed);
        tail->next.store(entry, std::memory_order_relaxed);
        return std::nullopt;
    }
};

template <typename T>
class MultipleConsumer {
  private:
    std::atomic<LFEntry<T>*> free_tail_{nullptr};
    std::atomic<LFEntry<T>*> head_{nullptr};

    void consumer_init(LFEntry<T>* head, LFEntry<T>* free_tail) {
        free_tail_.store(free_tail, std::memory_order_relaxed);
        head_.store(head, std::memory_order_relaxed);
    }

    template <typename U, template <typename> class Producer, template <typename> class Consumer>
    friend class LFQueue;

    void del_entry(LFEntry<T>* entry) {
        entry->next.store(nullptr, std::memory_order_relaxed);
        auto tail = free_tail_.exchange(entry, std::memory_order_relaxed);
        tail->next.store(entry, std::memory_order_relaxed);
    }

  public:
    std::optional<T> try_pop() {
        LFEntry<T>* head = nullptr;
        std::optional<T> ret;
        while ((head = head_.exchange(nullptr, std::memory_order_relaxed)) == nullptr);
        auto next = head->next.load(std::memory_order_relaxed);
        if (next == nullptr) {
            head_.store(head, std::memory_order_relaxed);
            ret = head->data.take();
        } else {
            ret = head->data.take();
            head_.store(next, std::memory_order_relaxed);
            del_entry(head);
        }
        return ret;
    }
};

template <typename Q>
class BlockingProducer {
  private:
    Q queue_;
    std::mutex mut_;
    std::condition_variable cv_;
    std::atomic<std::ptrdiff_t> count_{0};

  public:
    using value_type = typename Q::value_type;

    explicit BlockingProducer(size_t capacity) : queue_(capacity), count_(capacity) {}

    size_t capacity() const noexcept { return queue_.capacity(); }

    void notify_one_producer() {
        if (mut_.try_lock()) {
            mut_.unlock();
        }
        cv_.notify_one();
    }

    void notify_all_producers() {
        if (mut_.try_lock()) {
            mut_.unlock();
        }
        cv_.notify_all();
    }

    template <typename... Args>
    std::optional<value_type> try_push(Args&&... args) {
        auto fail = queue_.try_push(std::forward<Args>(args)...);
        if (!fail) {
            count_.fetch_sub(1, std::memory_order_relaxed);
        }
        return fail;
    }

    template <typename Pred, typename... Args>
    std::optional<value_type> try_push_do_while(Pred pred, Args&&... args) {
        bool flag = true;
        auto tmp = try_push(std::forward<Args>(args)...);
        while (tmp.has_value()) {
            {
                std::unique_lock<std::mutex> lock{mut_};
                cv_.wait(lock, [this, &flag, &pred] { return !(flag = pred()) || count_.load(std::memory_order_relaxed) > 0; });
            }
            if (!flag) { break; }
            tmp = try_push(*std::move(tmp));
        }
        return tmp;
    }

    template <typename Pred, typename... Args>
    std::optional<value_type> try_push_while(Pred&& pred, Args&&... args) {
        if (!pred()) { return std::optional<value_type>{std::in_place, std::forward<Args>(args)...}; }
        return try_push_do_while(std::forward<Pred>(pred), std::forward<Args>(args)...);
    }

    template <typename... Args>
    void push(Args&&... args) {
        return try_push_do_while([] { return true; }, std::forward<Args>(args)...);
    }

    std::optional<value_type> try_pop() {
        auto ret = queue_.try_pop();
        if (ret.has_value()) {
            count_.fetch_add(1, std::memory_order_relaxed);
            notify_one_producer();
        }
        return ret;
    }
};

template <typename Q>
class BlockingConsumer {
  private:
    Q queue_;
    std::mutex mut_;
    std::condition_variable cv_;
    std::atomic<std::ptrdiff_t> count_{0};

  public:
    using value_type = typename Q::value_type;

    explicit BlockingConsumer(size_t capacity) : queue_(capacity) {}

    size_t capacity() const noexcept { return queue_.capacity(); }

    void notify_one_consumer() {
        if (mut_.try_lock()) {
            mut_.unlock();
        }
        cv_.notify_one();
    }

    void notify_all_consumers() {
        if (mut_.try_lock()) {
            mut_.unlock();
        }
        cv_.notify_all();
    }

    template <typename... Args>
    std::optional<value_type> try_push(Args&&... args) {
        auto fail = queue_.try_push(std::forward<Args>(args)...);
        if (!fail) {
            count_.fetch_add(1, std::memory_order_relaxed);
            notify_one_consumer();
        }
        return fail;
    }

    std::optional<value_type> try_pop() {
        auto ret = queue_.try_pop();
        if (ret) {
            count_.fetch_sub(1, std::memory_order_relaxed);
        }
        return ret;
    }

    template <typename Pred>
    std::optional<value_type> try_pop_do_while(Pred pred) {
        bool flag = true;
        auto tmp = try_pop();
        while (!tmp.has_value()) {
            {
                std::unique_lock<std::mutex> lock{mut_};
                cv_.wait(lock, [this, &flag, &pred] { return !(flag = pred()) || count_.load(std::memory_order_relaxed) > 0; });
            }
            if (!flag) { break; }
            tmp = try_pop();
        }
        return tmp;
    }

    template <typename Pred>
    std::optional<value_type> try_pop_while(Pred&& pred) {
        if (!pred()) { return std::nullopt; }
        return try_pop_do_while(std::forward<Pred>(pred));
    }

    value_type pop() {
        return *try_pop_do_while([] { return true; });
    }
};

template <typename Q>
class BlockingProducer<BlockingConsumer<Q>> {
  private:
    Q queue_;
    std::mutex p_mut_;
    std::condition_variable p_cv_;
    std::mutex c_mut_;
    std::condition_variable c_cv_;
    std::atomic<std::ptrdiff_t> count_{0};
    const size_t cap_{0};

  public:
    using value_type = typename Q::value_type;

    explicit BlockingProducer(size_t capacity) : queue_(capacity), cap_(capacity) {}

    size_t capacity() const noexcept { return cap_; }

    void notify_one_producer() {
        if (p_mut_.try_lock()) {
            p_mut_.unlock();
        }
        p_cv_.notify_one();
    }

    void notify_all_producers() {
        if (p_mut_.try_lock()) {
            p_mut_.unlock();
        }
        p_cv_.notify_all();
    }

    void notify_one_consumer() {
        if (c_mut_.try_lock()) {
            c_mut_.unlock();
        }
        c_cv_.notify_one();
    }

    void notify_all_consumers() {
        if (c_mut_.try_lock()) {
            c_mut_.unlock();
        }
        c_cv_.notify_all();
    }

    template <typename... Args>
    std::optional<value_type> try_push(Args&&... args) {
        auto fail = queue_.try_push(std::forward<Args>(args)...);
        if (!fail) {
            count_.fetch_add(1, std::memory_order_relaxed);
            notify_one_consumer();
        }
        return fail;
    }

    template <typename Pred, typename... Args>
    std::optional<value_type> try_push_do_while(Pred pred, Args&&... args) {
        bool flag = true;
        auto tmp = try_push(std::forward<Args>(args)...);
        while (tmp) {
            {
                std::unique_lock<std::mutex> lock{p_mut_};
                p_cv_.wait(lock, [this, &flag, &pred] { return !(flag = pred()) || count_.load(std::memory_order_relaxed) < cap_; });
            }
            if (!flag) { break; }
            tmp = try_push(*std::move(tmp));
        }
        return tmp;
    }

    template <typename Pred, typename... Args>
    std::optional<value_type> try_push_while(Pred&& pred, Args&&... args) {
        if (!pred()) { return std::optional<value_type>{std::in_place, std::forward<Args>(args)...}; }
        return try_push_do_while(std::forward<Pred>(pred), std::forward<Args>(args)...);
    }

    template <typename... Args>
    void push(Args&&... args) {
        return try_push_do_while([] { return true; }, std::forward<Args>(args)...);
    }

    std::optional<value_type> try_pop() {
        auto ret = queue_.try_pop();
        if (ret) {
            count_.fetch_sub(1, std::memory_order_relaxed);
            notify_one_producer();
        }
        return ret;
    }

    template <typename Pred>
    std::optional<value_type> try_pop_do_while(Pred pred) {
        bool flag = true;
        auto tmp = try_pop();
        while (!tmp) {
            {
                std::unique_lock<std::mutex> lock{c_mut_};
                c_cv_.wait(lock, [this, &flag, &pred] { return !(flag = pred()) || count_.load(std::memory_order_relaxed) > 0; });
            }
            if (!flag) { break; }
            tmp = try_pop();
        }
        return tmp;
    }

    template <typename Pred>
    std::optional<value_type> try_pop_while(Pred&& pred) {
        if (!pred()) { return std::nullopt; }
        return try_pop_do_while(std::forward<Pred>(pred));
    }

    value_type pop() {
        return *try_pop_do_while([] { return true; });
    }
};

template <typename Q>
class BlockingConsumer<BlockingProducer<Q>> : public BlockingProducer<BlockingConsumer<Q>> {
  public:
    using BlockingProducer<BlockingConsumer<Q>>::BlockingProducer;
};

template <typename Q>
using Blocking = BlockingProducer<BlockingConsumer<Q>>;

template <typename T>
using Spsc = LFQueue<T, SingleProducer, SingleConsumer>;

template <typename T>
using Sbpsc = BlockingProducer<Spsc<T>>;

template <typename T>
using Spsbc = BlockingConsumer<Spsc<T>>;

template <typename T>
using Sbpsbc = Blocking<Spsc<T>>;

template <typename T>
using Spmc = LFQueue<T, SingleProducer, MultipleConsumer>;

template <typename T>
using Sbpmc = BlockingProducer<Spmc<T>>;

template <typename T>
using Spmbc = BlockingConsumer<Spmc<T>>;

template <typename T>
using Sbpmbc = Blocking<Spmc<T>>;

template <typename T>
using Mpsc = LFQueue<T, MultipleProducer, SingleConsumer>;

template <typename T>
using Mbpsc = BlockingProducer<Mpsc<T>>;

template <typename T>
using Mpsbc = BlockingConsumer<Mpsc<T>>;

template <typename T>
using Mbpsbc = Blocking<Mpsc<T>>;

template <typename T>
using Mpmc = LFQueue<T, MultipleProducer, MultipleConsumer>;

template <typename T>
using Mbpmc = BlockingProducer<Mpmc<T>>;

template <typename T>
using Mpmbc = BlockingConsumer<Mpmc<T>>;

template <typename T>
using Mbpmbc = Blocking<Mpmc<T>>;

template <typename T>
class LFStack {
  private:
    std::atomic<LFEntry<T>*> stack_{nullptr};
    std::atomic<LFEntry<T>*> free_{nullptr};

    LFEntry<T>* try_new_entry() {
        auto free = free_.load(std::memory_order_relaxed);
        LFEntry<T>* next = nullptr;
        do {
            if (free == nullptr) {
                return nullptr;
            }
            next = free->next.load(std::memory_order_relaxed);
        } while (!free_.compare_exchange_strong(free, next, std::memory_order_relaxed));
        free->next.store(nullptr, std::memory_order_relaxed);
        return free;
    }

    LFEntry<T>* new_entry() {
        auto entry = try_new_entry();
        if (entry == nullptr) {
            entry = new LFEntry<T>;
        }
        return entry;
    }

    void del_entry(LFEntry<T>* entry) {
        auto free = free_.load(std::memory_order_relaxed);
        do {
            entry->next.store(free, std::memory_order_relaxed);
        } while (!free_.compare_exchange_strong(free, entry, std::memory_order_relaxed));
    }

  public:
    LFStack() = default;
    LFStack(const LFStack&) = delete;
    LFStack(LFStack&&) = delete;
    LFStack& operator=(const LFStack&) = delete;
    LFStack& operator=(LFStack&&) = delete;

    ~LFStack() {
        LFEntry<T>* entry;
        while (try_pop());
        while ((entry = try_new_entry()) != nullptr) {
            delete entry;
        }
    }

    template <typename... Args>
    void push(Args&&... args) {
        auto entry = new_entry();
        entry->data.set(std::forward<Args>(args)...);
        auto stack = stack_.load(std::memory_order_relaxed);
        do {
            entry->next.store(stack, std::memory_order_relaxed);
        } while (!stack_.compare_exchange_strong(stack, entry, std::memory_order_relaxed));
    }

    std::optional<T> try_pop() {
        auto stack = stack_.load(std::memory_order_relaxed);
        LFEntry<T>* next = nullptr;
        do {
            if (stack == nullptr) {
                return std::nullopt;
            }
            next = stack->next.load(std::memory_order_relaxed);
        } while (!stack_.compare_exchange_strong(stack, next, std::memory_order_relaxed));
        stack->next.store(nullptr, std::memory_order_relaxed);
        auto ret = stack->data.take();
        del_entry(stack);
        return ret;
    }
};

#endif
