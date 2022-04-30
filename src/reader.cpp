#include <fastcap/reader.hpp>
#include <fastcap/utils.hpp>

#include <spdlog/spdlog.h>

void Reader::read(void* buf, std::streamsize len) {
    file_.read(reinterpret_cast<char*>(buf), len);
}

void Reader::read(std::string* buf) {
    std::getline(file_, *buf, '\0');
}

template <typename T>
void Reader::read(T* buf) {
    read(buf, sizeof(T));
}

void Reader::read_next() {
    if (file_.eof()) {
        done_ = true;
        return;
    }

    uint64_t entry_id = 0;
    read(&entry_id);
    if (file_.eof()) {
        done_ = true;
        return;
    }
    if ((entry_id & (1ull << 63)) > 0) {
        auto& hdr = hdr_.template emplace<StatHdr>();
        hdr.id = entry_id & ~(1ull << 63);
        read(reinterpret_cast<char*>(&hdr) + sizeof(uint64_t), sizeof(StatHdr) - sizeof(uint64_t));
        if (native_ == 0) {
            hdr.id = byteswap(hdr.id);
            hdr.secs = byteswap(hdr.secs);
            hdr.frac = byteswap(hdr.frac);
            hdr.recv = byteswap(hdr.recv);
            hdr.iface_drops = byteswap(hdr.iface_drops);
            hdr.os_drops = byteswap(hdr.os_drops);
        }
    } else {
        auto& hdr = hdr_.template emplace<PktHdr>();
        hdr.id = entry_id;
        read(reinterpret_cast<char*>(&hdr) + sizeof(uint64_t), sizeof(PktHdr) - sizeof(uint64_t));
        data_.resize(hdr.caplen);
        read(data_.data(), data_.size());
        if (native_ == 0) {
            hdr.id = byteswap(hdr.id);
            hdr.secs = byteswap(hdr.secs);
            hdr.frac = byteswap(hdr.frac);
            hdr.len = byteswap(hdr.len);
            hdr.caplen = byteswap(hdr.caplen);
        }
    }
}

Reader::Reader(const std::string& path) : file_(path) {
    constexpr uint32_t NATIVE_MAGIC = 0x46434150;
    constexpr uint32_t NON_NATIVE_MAGIC = 0x50414346;
    uint32_t magic = 0;
    read(&magic);
    if (magic == NATIVE_MAGIC) {
        native_ = 1;
    } else if (magic == NON_NATIVE_MAGIC) {
        native_ = 0;
    } else {
        spdlog::error("{} is not a fastcap file", path);
        native_ = -1;
        return;
    }

    uint64_t entry_id = 0;
    read(&entry_id);
    file_.seekg(-static_cast<std::streamoff>(sizeof(uint64_t)), std::ios::cur);
    has_lead_ = entry_id == 0;
}

void ReaderSet::read_lead(Reader& r) {
    uint64_t entry_id = 0;
    r.read(&entry_id);
    r.read(&cpu_model_);
    r.read(&os_version_);
    r.read(&dev_name_);
    uint8_t nano = 0;
    r.read(&nano);
    nano_ = nano != 0;
    r.read(&filter_);
    r.read(&snaplen_);
    if (r.native_ == 0) {
        snaplen_ = byteswap(snaplen_);
    }
    uint32_t ipv4_count = 0;
    r.read(&ipv4_count);
    if (r.native_ == 0) {
        ipv4_count = byteswap(ipv4_count);
    }
    for (uint32_t i = 0; i < ipv4_count; ++i) {
        auto& ipv4 = ipv4s_.emplace_back();
        r.read(ipv4.addr.data(), 4);
        r.read(ipv4.mask.data(), 4);
    }
    uint32_t ipv6_count = 0;
    r.read(&ipv6_count);
    if (r.native_ == 0) {
        ipv6_count = byteswap(ipv6_count);
    }
    for (uint32_t i = 0; i < ipv6_count; ++i) {
        auto& ipv6 = ipv6s_.emplace_back();
        r.read(ipv6.addr.data(), 16);
        r.read(&ipv6.prefix_len);
    }
    uint8_t has_mac = 0;
    r.read(&has_mac);
    if (has_mac != 0) {
        mac_.emplace();
        r.read(mac_->data(), 6);
    }
    r.read(&hardware_);
    r.read(&speed_);
    if (r.native_ == 0) {
        speed_ = byteswap(speed_);
    }
    r.read(&link_);
    if (r.native_ == 0) {
        link_ = byteswap(link_);
    }

    auto pos = r.file_.tellg();
    r.file_.seekg(8, std::ios::cur);
    r.read(&start_sec_);
    if (r.native_ == 0) {
        start_sec_ = byteswap(start_sec_);
    }
    r.read(&start_frac_);
    if (r.native_ == 0) {
        start_frac_ = byteswap(start_frac_);
    }
    r.file_.seekg(pos);
}

ReaderSet::ReaderSet(const std::vector<std::string>& paths) {
    readers_.reserve(paths.size());
    bool ok = true;
    for (auto path : paths) {
        auto& reader = readers_.emplace_back(path);
        if (reader.native_ < 0) {
            ok = false;
            continue;
        }
        if (reader.has_lead_) {
            read_lead(reader);
        }
    }
    if (!ok) {
        std::exit(1);
    }
    for (auto& reader : readers_) {
        reader.read_next();
    }
}

std::optional<std::variant<PktHdr, StatHdr>>
ReaderSet::next(std::vector<uint8_t>& data) {
    for (;;) {
        size_t done_count = 0;
        for (auto& reader : readers_) {
            if (!reader.done_) {
                auto [id, is_pkt] = std::visit([](const auto& hdr) -> std::pair<uint64_t, bool> {
                    using hdr_t = std::decay_t<decltype(hdr)>;
                    return {hdr.id, std::is_same_v<hdr_t, PktHdr>};
                }, reader.hdr_);
                if (id == next_) {
                    ++next_;
                    if (is_pkt) {
                        std::swap(data, reader.data_);
                    }
                    auto hdr = reader.hdr_;
                    reader.read_next();
                    return hdr;
                }
            } else {
                ++done_count;
            }
        }
        if (done_count == readers_.size()) {
            return std::nullopt;
        }
        spdlog::warn("missing entry {}", next_);
        ++next_;
    }
}

const std::string& ReaderSet::cpu_model() const {
    return cpu_model_;
}

const std::string& ReaderSet::os_version() const {
    return os_version_;
}

const std::string& ReaderSet::device_name() const {
    return dev_name_;
}

bool ReaderSet::nanosecond_precision() const {
    return nano_;
}

const std::string& ReaderSet::capture_filter() const {
    return filter_;
}

int ReaderSet::snaplen() const {
    return snaplen_;
}

const std::vector<IPv4Subnet>& ReaderSet::ipv4s() const {
    return ipv4s_;
}

const std::vector<IPv6Subnet>& ReaderSet::ipv6s() const {
    return ipv6s_;
}

const std::optional<MAC>& ReaderSet::mac() const {
    return mac_;
}

const std::string& ReaderSet::hardware() const {
    return hardware_;
}

uint64_t ReaderSet::speed() const {
    return speed_;
}

uint16_t ReaderSet::link() const {
    return link_;
}

uint64_t ReaderSet::start_seconds() const {
    return start_sec_;
}

uint64_t ReaderSet::start_fraction() const {
    return start_frac_;
}
