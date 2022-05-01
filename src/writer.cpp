#include <fastcap/writer.hpp>
#include <fastcap/sysinfo.hpp>
#include <fastcap/device.hpp>
#include <cstring>
#include <filesystem>
#include <spdlog/fmt/fmt.h>
#include <pcap.h>
#include <spdlog/spdlog.h>

void write(std::ofstream& f, const void* data, std::streamsize len) {
    f.write(reinterpret_cast<const char*>(data), len);
}

WriterSet::WriterSet(const Config& config, int datalink) : buf_(config.bufsz) {
    if (config.num_files == 1) {
        writers_.emplace_back(*this, std::ofstream(config.fname, std::ios::binary));
    } else {
        writers_.reserve(config.num_files);
        auto ext = std::filesystem::path(config.fname).extension().string();
        auto fname = config.fname.substr(0, config.fname.size() - ext.size());
        for (int i = 0; i < config.num_files; ++i) {
            writers_.emplace_back(*this, std::ofstream(fmt::format("{}.{}{}", fname, i, ext)));
        }
    }

    const uint32_t magic = 0x46434150;
    for (auto& writer : writers_) {
        write(writer.file_, &magic, sizeof(magic));
    }

    auto& f = writers_.front().file_;
    uint64_t entry_id = 0;
    write(f, &entry_id, sizeof(entry_id));
    auto cpu = cpu_model();
    auto os = os_version();
    auto dev = Device{config.iface};
    write(f, cpu.c_str(), cpu.size() + 1);
    write(f, os.c_str(), os.size() + 1);
    auto name = dev.name();
    write(f, name.c_str(), name.size() + 1);
    uint8_t nano = config.nano ? 1 : 0;
    write(f, &nano, 1);
    write(f, config.filter.c_str(), config.filter.size() + 1);
    write(f, &config.snaplen, sizeof(int));
    auto ipv4s = dev.ipv4_addrs();
    auto ipv4_count = static_cast<uint32_t>(ipv4s.size());
    write(f, &ipv4_count, sizeof(ipv4_count));
    for (const auto& ipv4 : ipv4s) {
        write(f, ipv4.addr.data(), 4);
        write(f, ipv4.mask.data(), 4);
    }
    auto ipv6s = dev.ipv6_addrs();
    auto ipv6_count = static_cast<uint32_t>(ipv6s.size());
    write(f, &ipv6_count, sizeof(ipv6_count));
    for (const auto& ipv6 : ipv6s) {
        write(f, ipv6.addr.data(), 16);
        write(f, &ipv6.prefix_len, 1);
    }
    auto mac = dev.mac_addr();
    if (mac) {
        uint8_t has_mac = 0;
        write(f, &has_mac, 1);
    } else {
        uint8_t has_mac = 1;
        write(f, &has_mac, 1);
        write(f, mac->data(), 6);
    }
    auto hw = dev.hardware();
    write(f, hw.c_str(), hw.size() + 1);
    auto speed = dev.speed();
    write(f, &speed, sizeof(speed));
    auto link = static_cast<uint16_t>(datalink);
    write(f, &link, sizeof(link));

    ++entry_count_;

    for (auto& writer : writers_) {
        writer.launch_worker();
    }
}

void WriterSet::write_packet(const pcap_pkthdr& hdr, const uint8_t* bytes) {
    if (buf_.prepare_write(sizeof(PktHdr) + hdr.caplen)) {
        PktHdr phdr {
            entry_count_,
            static_cast<uint64_t>(hdr.ts.tv_sec),
            static_cast<uint64_t>(hdr.ts.tv_usec),
            hdr.len,
            hdr.caplen
        };
        buf_.write_some(reinterpret_cast<uint8_t*>(&phdr), sizeof(PktHdr));
        buf_.write_some(bytes, phdr.caplen);
        buf_.commit_write();
        ++entry_count_;
    }
}

void WriterSet::write_stats(const timeval& ts, uint64_t recv, uint64_t iface_drops, uint64_t os_drops) {
    if (buf_.prepare_write(sizeof(StatHdr))) {
        StatHdr hdr {
            entry_count_ | (1ull << 63),
            static_cast<uint64_t>(ts.tv_sec),
            static_cast<uint64_t>(ts.tv_usec),
            recv,
            iface_drops,
            os_drops
        };
        buf_.write_some(reinterpret_cast<uint8_t*>(&hdr), sizeof(StatHdr));
        buf_.commit_write();
        ++entry_count_;

        spdlog::info("received: {}, interface dropped: {}, OS dropped: {}", hdr.recv, hdr.iface_drops, hdr.os_drops);
    }
}

int WriterSet::join() {
    stop_.store(true, std::memory_order_relaxed);
    buf_.notify_all_consumers();
    for (auto& writer : writers_) {
        writer.join();
    }
    return 0;
}

Writer::Writer(WriterSet& set, std::ofstream file)
    : file_(std::move(file)),
      set_(&set) {
}

void Writer::work() {
    std::vector<uint8_t> buf;
    buf.reserve(1600);
    while (set_->buf_.try_read_while([this] {
        return !set_->stop_.load(std::memory_order_relaxed);
    }, buf)) {
        file_.write(reinterpret_cast<const char*>(buf.data()), buf.size());
    }
}

void Writer::launch_worker() {
    worker_ = std::thread([this] { work(); });
}

void Writer::join() {
    worker_.join();
}
