#include <fastcap/pcapng.hpp>
#include <spdlog/spdlog.h>

static std::array<uint8_t, 4> PADDING = {0, 0, 0, 0};

void PcapNGWriter::write(const void* buf, std::streamsize len) {
    file_.write(reinterpret_cast<const char*>(buf), len);
}

template <typename T>
void PcapNGWriter::write(const T* buf) {
    write(buf, sizeof(T));
}

std::streamoff PcapNGWriter::position() {
    return file_.tellp();
}

void PcapNGWriter::seek(std::streamoff pos) {
    file_.seekp(pos);
}

template <typename T>
T padding(T len) {
    return (4 - (len % 4)) % 4;
}

void PcapNGWriter::write_shb() {
    const uint32_t shb_id = 0x0A0D0D0A;
    const uint32_t magic = 0x1A2B3C4D;
    const uint16_t major = 1;
    const uint16_t minor = 0;
    const uint64_t section_len = 0xFFFFFFFFFFFFFFFF;
    uint32_t block_len = 0;
    write(&shb_id);
    auto block_len_pos = position();
    write(&block_len);
    write(&magic);
    write(&major);
    write(&minor);
    write(&section_len);
    
    uint16_t opt_id = 2;
    uint16_t opt_len = static_cast<uint16_t>(readers_->cpu_model().size());
    auto padding_len = padding(opt_len);
    write(&opt_id);
    write(&opt_len);
    write(readers_->cpu_model().c_str(), readers_->cpu_model().size());
    if (padding_len != 0) {
        write(PADDING.data(), padding_len);
    }

    opt_id = 3;
    opt_len = static_cast<uint16_t>(readers_->os_version().size());
    padding_len = padding(opt_len);
    write(&opt_id);
    write(&opt_len);
    write(readers_->os_version().c_str(), readers_->os_version().size());
    if (padding_len != 0) {
        write(PADDING.data(), padding_len);
    }

    const std::string_view app_name = "Fastcap";
    opt_id = 4;
    opt_len = static_cast<uint16_t>(app_name.size());
    padding_len = padding(opt_len);
    write(&opt_id);
    write(&opt_len);
    write(app_name.data(), app_name.size());
    if (padding_len != 0) {
        write(PADDING.data(), padding_len);
    }

    opt_id = 0;
    opt_len = 0;
    write(&opt_id);
    write(&opt_len);
    auto tmp = position();
    block_len = (tmp - block_len_pos) + 8;
    seek(block_len_pos);
    write(&block_len);
    seek(tmp);
    write(&block_len);
}

void PcapNGWriter::write_idb() {
    const uint32_t idb_id = 1;
    uint32_t block_len = 0;
    uint16_t link = readers_->link();
    uint16_t reserved = 0;
    auto snaplen = static_cast<uint32_t>(readers_->snaplen());
    write(&idb_id);
    auto block_len_pos = position();
    write(&block_len);
    write(&link);
    write(&reserved);
    write(&snaplen);

    uint16_t opt_id = 2;
    uint16_t opt_len = static_cast<uint16_t>(readers_->device_name().size());
    uint16_t padding_len = padding(opt_len);
    write(&opt_id);
    write(&opt_len);
    write(readers_->device_name().c_str(), readers_->device_name().size());
    if (padding_len != 0) {
        write(PADDING.data(), padding_len);
    }

    opt_id = 4;
    opt_len = 8;
    for (const auto& ipv4 : readers_->ipv4s()) {
        write(&opt_id);
        write(&opt_len);
        write(ipv4.addr.data(), 4);
        write(ipv4.mask.data(), 4);
    }

    opt_id = 5;
    opt_len = 17;
    for (const auto& ipv6 : readers_->ipv6s()) {
        write(&opt_id);
        write(&opt_len);
        write(ipv6.addr.data(), 16);
        write(&ipv6.prefix_len);
        write(PADDING.data(), 3);
    }

    if (readers_->mac().has_value()) {
        opt_id = 6;
        opt_len = 6;
        write(&opt_id);
        write(&opt_len);
        write(readers_->mac()->data(), 6);
        write(PADDING.data(), 2);
    }

    opt_id = 8;
    opt_len = 8;
    auto speed = readers_->speed();
    write(&opt_id);
    write(&opt_len);
    write(&speed);

    opt_id = 9;
    opt_len = 1;
    uint8_t tsresol = readers_->nanosecond_precision() ? 9 : 6;
    write(&opt_id);
    write(&opt_len);
    write(&tsresol);
    write(PADDING.data(), 3);

    if (!readers_->capture_filter().empty()) {
        opt_id = 11;
        opt_len = static_cast<uint16_t>(readers_->capture_filter().size() + 1);
        uint8_t prefix = 0;
        padding_len = padding(opt_len);
        write(&opt_id);
        write(&opt_len);
        write(&prefix);
        write(readers_->capture_filter().c_str(), readers_->capture_filter().size());
        if (padding_len != 0) {
            write(PADDING.data(), padding_len);
        }
    }

    opt_id = 12;
    opt_len = static_cast<uint16_t>(readers_->os_version().size());
    padding_len = padding(opt_len);
    write(&opt_id);
    write(&opt_len);
    write(readers_->os_version().c_str(), readers_->os_version().size());
    if (padding_len != 0) {
        write(PADDING.data(), padding_len);
    }

    opt_id = 14;
    opt_len = 8;
    auto tsoffset = readers_->start_seconds();
    write(&opt_id);
    write(&opt_len);
    write(&tsoffset);

    opt_id = 15;
    opt_len = static_cast<uint16_t>(readers_->hardware().size());
    padding_len = padding(opt_len);
    write(&opt_id);
    write(&opt_len);
    write(readers_->hardware().c_str(), readers_->hardware().size());
    if (padding_len != 0) {
        write(PADDING.data(), padding_len);
    }

    opt_id = 0;
    opt_len = 0;
    write(&opt_id);
    write(&opt_len);

    auto tmp = position();
    block_len = static_cast<uint32_t>(tmp - block_len_pos) + 8;
    seek(block_len_pos);
    write(&block_len);
    seek(tmp);
    write(&block_len);
}

std::pair<uint32_t, uint32_t> PcapNGWriter::timestamp(uint64_t sec, uint64_t frac) {
    sec -= readers_->start_seconds();
    if (readers_->nanosecond_precision()) {
        sec *= 1'000'000'000;
    } else {
        sec *= 1'000'000;
    }
    sec += frac;
    uint32_t hi = static_cast<uint32_t>(sec >> 32);
    uint32_t lo = static_cast<uint32_t>(sec & 0xFFFFFFFF);
    return {hi, lo};
}

void PcapNGWriter::write_epb(const PktHdr& hdr, const std::vector<uint8_t>& data) {
    const uint32_t epb_id = 6;
    const uint32_t iface_id = 0;
    auto [ts_hi, ts_lo] = timestamp(hdr.secs, hdr.frac);
    auto caplen = hdr.caplen;
    auto origlen = hdr.len;
    auto padding_len = padding(data.size());
    uint32_t block_len = static_cast<uint32_t>(32 + data.size() + padding_len);

    write(&epb_id);
    write(&block_len);
    write(&iface_id);
    write(&ts_hi);
    write(&ts_lo);
    write(&caplen);
    write(&origlen);
    write(data.data(), data.size());
    if (padding_len != 0) {
        write(PADDING.data(), padding_len);
    }
    write(&block_len);

    ++pkt_count_;
}

void PcapNGWriter::write_isb(const StatHdr& hdr) {
    const uint32_t isb_id = 5;
    const uint32_t block_len = 64;
    const uint32_t iface_id = 0;
    auto [ts_hi, ts_lo] = timestamp(hdr.secs, hdr.frac);

    write(&isb_id);
    write(&block_len);
    write(&iface_id);
    write(&ts_hi);
    write(&ts_lo);
    
    uint16_t opt_id = 4;
    uint16_t opt_len = 8;
    write(&opt_id);
    write(&opt_len);
    write(&hdr.recv);
    
    opt_id = 5;
    opt_len = 8;
    write(&opt_id);
    write(&opt_len);
    write(&hdr.iface_drops);
    
    opt_id = 7;
    opt_len = 8;
    write(&opt_id);
    write(&opt_len);
    write(&hdr.os_drops);

    opt_id = 0;
    opt_len = 0;
    write(&opt_id);
    write(&opt_len);

    write(&block_len);
}

PcapNGWriter::PcapNGWriter(const std::string& filepath, ReaderSet& readers)
    : file_(filepath), readers_(&readers) {}

void PcapNGWriter::write_all() {
    const auto ONE_SEC = std::chrono::duration_cast<std::chrono::high_resolution_clock::duration>(std::chrono::seconds(1));
    auto timer_end = std::chrono::high_resolution_clock::now() + ONE_SEC;
    write_shb();
    write_idb();
    std::vector<uint8_t> data;
    bool just_logged = false;
    for (;;) {
        auto entry = readers_->next(data);
        if (!entry.has_value()) {
            break;
        }
        std::visit([this, &data](const auto& hdr) {
            using hdr_t = std::decay_t<decltype(hdr)>;
            if constexpr (std::is_same_v<hdr_t, PktHdr>) {
                write_epb(hdr, data);
            } else {
                write_isb(hdr);
            }
        }, *entry);
        if (std::chrono::high_resolution_clock::now() >= timer_end) {
            timer_end += ONE_SEC;
            spdlog::info("{} packets written", pkt_count_);
            just_logged = true;
        } else {
            just_logged = false;
        }
    }
    spdlog::info("{} packets written", pkt_count_);
}

void write_pcapng(const std::string& in_file, ReaderSet& readers) {
    PcapNGWriter writer{in_file, readers};
    writer.write_all();
}

void write_pcapng(const std::string& out_file, const std::vector<std::string>& in_files) {
    ReaderSet readers{in_files};
    write_pcapng(out_file, readers);
}
