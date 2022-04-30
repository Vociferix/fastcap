#ifndef FASTCAP_READER_HPP
#define FASTCAP_READER_HPP

#include <fastcap/device.hpp>
#include <fastcap/writer.hpp>

#include <variant>

class ReaderSet;

class Reader {
  private:
    std::ifstream file_;
    std::variant<PktHdr, StatHdr> hdr_;
    std::vector<uint8_t> data_;
    int native_{0};
    bool has_lead_{false};
    bool done_{false};

    friend class ReaderSet;

    void read(void* buf, std::streamsize len);
    void read(std::string* buf);

    template <typename T>
    void read(T* buf);

    void read_next();

  public:
    explicit Reader(const std::string& path);
};

class ReaderSet {
  private:
    std::vector<Reader> readers_;
    std::string cpu_model_;
    std::string os_version_;
    std::string dev_name_;
    bool nano_{false};
    std::string filter_;
    int snaplen_;
    std::vector<IPv4Subnet> ipv4s_;
    std::vector<IPv6Subnet> ipv6s_;
    std::optional<MAC> mac_;
    std::string hardware_;
    uint64_t speed_{0};
    uint16_t link_{0};
    uint64_t start_sec_{0};
    uint64_t start_frac_{0};
    uint64_t next_{1};

    void read_lead(Reader& r);

  public:
    ReaderSet(const std::vector<std::string>& paths);

    std::optional<std::variant<PktHdr, StatHdr>> next(std::vector<uint8_t>& data);

    const std::string& cpu_model() const;
    const std::string& os_version() const;
    const std::string& device_name() const;
    bool nanosecond_precision() const;
    const std::string& capture_filter() const;
    int snaplen() const;
    const std::vector<IPv4Subnet>& ipv4s() const;
    const std::vector<IPv6Subnet>& ipv6s() const;
    const std::optional<MAC>& mac() const;
    const std::string& hardware() const;
    uint64_t speed() const;
    uint16_t link() const;
    uint64_t start_seconds() const;
    uint64_t start_fraction() const;
};

#endif
