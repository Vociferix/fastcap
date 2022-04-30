#ifndef FASTCAP_UTILS_HPP
#define FASTCAP_UTILS_HPP

#include <cstdint>

template <typename F>
class Finally {
  private:
    F fin_;

  public:
    explicit Finally(F&& fin) : fin_(std::forward<F>(fin)) {}

    ~Finally() {
        fin_();
    }

    Finally(const Finally&) = delete;
    Finally(Finally&&) = delete;
    Finally& operator=(const Finally&) = delete;
    Finally& operator=(Finally&&) = delete;
};

template <typename F>
Finally<F> finally(F&& fin) {
    return Finally<F>(std::forward<F>(fin));
}

inline uint16_t byteswap(uint16_t x) {
    return __builtin_bswap16(x);
}

inline uint32_t byteswap(uint32_t x) {
    return __builtin_bswap32(x);
}

inline uint64_t byteswap(uint64_t x) {
    return __builtin_bswap64(x);
}

inline int16_t byteswap(int16_t x) {
    return static_cast<int16_t>(byteswap(static_cast<uint16_t>(x)));
}

inline int32_t byteswap(int32_t x) {
    return static_cast<int32_t>(byteswap(static_cast<uint32_t>(x)));
}

inline int64_t byteswap(int64_t x) {
    return static_cast<int64_t>(byteswap(static_cast<uint64_t>(x)));
}

#endif
