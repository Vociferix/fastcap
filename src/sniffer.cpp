#include <fastcap/sniffer.hpp>
#include <fastcap/utils.hpp>

#include <spdlog/spdlog.h>

#include <pcap.h>
#include <sys/eventfd.h>
#include <poll.h>
#include <unistd.h>

#include <chrono>
#include <cstdint>
#include <limits>

Sniffer::Sniffer(const Config& config) : stats_interval_(config.stats_interval) {
    char err_buf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = nullptr;
    auto stop_event = eventfd(0, 0);
    if (stop_event < 0) {
        spdlog::error("failed to create sniffer stop event: {}", strerror(errno));
        return;
    }
    auto guard = finally([&pcap, &stop_event] {
        if (stop_event >= 0) {
            close(stop_event);
        }
        if (pcap != nullptr) {
            pcap_close(pcap);
            close(stop_event);
        }
    });

    pcap = pcap_create(config.iface.c_str(), err_buf);
    if (pcap == nullptr) {
        spdlog::error("{}", err_buf);
        return;
    }

    pcap_set_snaplen(pcap, config.snaplen);
    pcap_set_promisc(pcap, config.promisc ? 1 : 0);
    switch (pcap_can_set_rfmon(pcap)) {
        case PCAP_ERROR_NO_SUCH_DEVICE:
            spdlog::error("no such interface {}", config.iface);
            return;
        case PCAP_ERROR_PERM_DENIED:
            if (config.rfmon) {
                spdlog::error("user does not have permissions to put {} in monitor mode", config.iface);
                return;
            }
            break;
        case PCAP_ERROR:
            spdlog::error("{}", pcap_geterr(pcap));
            return;
        case 1:
            pcap_set_rfmon(pcap, config.rfmon ? 1 : 0);
            break;
        case 0:
            if (config.rfmon) {
                spdlog::error("interface {} cannot be put into monitor mode", config.iface);
                return;
            }
            break;
        default:
            break;
    }
    pcap_set_immediate_mode(pcap, config.immediate ? 1 : 0);
    if (!config.immediate) {
        pcap_set_timeout(pcap, std::numeric_limits<int>::max());
    }
    pcap_set_buffer_size(pcap, config.bufsz);
    if (pcap_set_tstamp_type(pcap, PCAP_TSTAMP_ADAPTER) != 0) {
        pcap_set_tstamp_type(pcap, PCAP_TSTAMP_HOST_HIPREC);
    }
    if (pcap_set_tstamp_precision(pcap, config.nano ? PCAP_TSTAMP_PRECISION_NANO : PCAP_TSTAMP_PRECISION_MICRO) != 0) {
        if (config.nano) {
            spdlog::error("interface {} does not support nanosecond timestamp precision", config.iface);
            return;
        } else {
            spdlog::error("interface {} does not support microsecond timestamp precision", config.iface);
            return;
        }
    }

    switch (pcap_activate(pcap)) {
        case PCAP_WARNING_PROMISC_NOTSUP:
            spdlog::error("interface {} does not support promiscuous mode: {}", pcap_geterr(pcap));
            return;
        case PCAP_WARNING_TSTAMP_TYPE_NOTSUP:
            break;
        case PCAP_WARNING:
            spdlog::warn("{}", pcap_geterr(pcap));
            break;
        case PCAP_ERROR_NO_SUCH_DEVICE:
            spdlog::error("no such interface {}: {}", config.iface, pcap_geterr(pcap));
            return;
        case PCAP_ERROR_PERM_DENIED:
            spdlog::error("permission denied: {}", pcap_geterr(pcap));
            return;
        case PCAP_ERROR_PROMISC_PERM_DENIED:
            spdlog::error("user does not have permissions to put interface {} in promiscuous mode", config.iface);
            return;
        case PCAP_ERROR_RFMON_NOTSUP:
            spdlog::error("interface {} does not support monitor mode", config.iface);
            return;
        case PCAP_ERROR:
            spdlog::error("{}", pcap_geterr(pcap));
            return;
    }

    datalink_ = pcap_datalink(pcap);

    if (pcap_setnonblock(pcap, 1, err_buf) != 0) {
        spdlog::error("unable to put capture in non-blocking mode: {}", err_buf);
        return;
    }

    if (!config.filter.empty()) {
        prog_ = new bpf_program;
        if (pcap_compile(pcap, prog_, config.filter.c_str(), 1, PCAP_NETMASK_UNKNOWN) != 0) {
            spdlog::error("failed to compile filter: {}", pcap_geterr(pcap));
            delete prog_;
            prog_ = nullptr;
            return;
        }

        if (pcap_setfilter(pcap, prog_) != 0) {
            spdlog::error("failed to apply filter: {}", pcap_geterr(pcap));
            pcap_freecode(prog_);
            delete prog_;
            prog_ = nullptr;
            return;
        }
    }

    std::swap(pcap_, pcap);
    std::swap(stop_event_, stop_event);
}

Sniffer::~Sniffer() {
    if (pcap_ != nullptr) {
        pcap_close(pcap_);
        pcap_ = nullptr;
        close(stop_event_);
        stop_event_ = -1;
        if (prog_ != nullptr) {
            pcap_freecode(prog_);
            delete prog_;
            prog_ = nullptr;
        }
    }
}

int Sniffer::datalink() const {
    return datalink_;
}

bool Sniffer::ok() {
    return pcap_ != nullptr;
}

static void sniff_callback_c(u_char* user, const pcap_pkthdr* h, const u_char* bytes) {
    auto [sniffer, writers] = *reinterpret_cast<std::pair<Sniffer*, WriterSet*>*>(user);
    sniffer->sniff_callback(*writers, *h, bytes);
}

int Sniffer::run(WriterSet& writers) {
    if (!ok()) { return 1; }

    pollfd events[2] = {
        {
            stop_event_,
            POLLIN,
            0
        },
        {
            pcap_get_selectable_fd(pcap_),
            POLLIN,
            0
        }
    };
    auto& stop_poll = events[0];
    auto& pcap_poll = events[1];
    auto timeout_ptr = pcap_get_required_select_timeout(pcap_);
    int timeout = -1;
    if (timeout_ptr != nullptr) {
        timeout = timeout_ptr->tv_sec * 1000;
        timeout += timeout_ptr->tv_usec / 1000;
    }

    const auto interval = std::chrono::duration_cast<std::chrono::high_resolution_clock::duration>(std::chrono::duration<float>(stats_interval_));
    const bool do_stats = stats_interval_ >= 0.0f;
    auto start = std::chrono::high_resolution_clock::now();
    bool just_did_stats = false;
    while (!stop_flag_.load(std::memory_order_relaxed)) {
        switch (poll(events, 2, timeout)) {
            case -1:
                spdlog::error("failed to poll interface: {}", strerror(errno));
                return 1;
            case 0:
                continue;
            default:
                break;
        }

        if (stop_poll.revents != 0) {
            break;
        }

        if (pcap_poll.revents != 0) {
            std::pair<Sniffer*, WriterSet*> user{this, &writers};
            if (pcap_dispatch(pcap_, -1, sniff_callback_c, reinterpret_cast<u_char*>(&user)) == PCAP_ERROR) {
                spdlog::error("capture error: {}", pcap_geterr(pcap_));
                return 1;
            }

            if (do_stats) {
                auto end = std::chrono::high_resolution_clock::now();
                if (end - start >= interval) {
                    start = end;
                    stats(writers);
                    just_did_stats = true;
                } else {
                    just_did_stats = false;
                }
            }
        }
    }
    if (!just_did_stats) {
        stats(writers);
    }

    return 0;
}

int Sniffer::stop() {
    stop_flag_.store(true, std::memory_order_relaxed);
    const uint64_t value = 1;
    if (write(stop_event_, &value, 8) < 0) {
        spdlog::error("failed to stop sniffer: {}", strerror(errno));
        return 1;
    }
    return 0;
}

void Sniffer::sniff_callback(WriterSet& writers, const pcap_pkthdr& hdr, const uint8_t* bytes) {
    writers.write_packet(hdr, bytes);
    last_ts_ = hdr.ts;
}

void Sniffer::stats(WriterSet& writers) {
    pcap_stat stats{};
    if (pcap_stats(pcap_, &stats) != 0) {
        spdlog::error("failed to collect capture statistics: {}", pcap_geterr(pcap_));
        return;
    }

    writers.write_stats(last_ts_, stats.ps_recv, stats.ps_ifdrop, stats.ps_drop);
}
