#ifndef FASTCAP_SNIFFER_HPP
#define FASTCAP_SNIFFER_HPP

#include <fastcap/config.hpp>
#include <fastcap/writer.hpp>

#include <cstdint>
#include <optional>

#include <sys/time.h>

extern "C" {
struct pcap;
struct pcap_pkthdr;
struct bpf_program;
}

class Sniffer {
  public:
    explicit Sniffer(const Config& cfg);
    Sniffer(const Sniffer&) = delete;
    Sniffer(Sniffer&& other) = delete;
    ~Sniffer();
    Sniffer& operator=(const Sniffer&) = delete;
    Sniffer& operator=(Sniffer&&) = delete;

    int datalink() const;

    bool ok();
    int run(WriterSet& writers);
    int stop();

    void sniff_callback(WriterSet& writers, const pcap_pkthdr& hdr, const uint8_t* bytes);

  private:
    void stats(WriterSet& writers);

    pcap* pcap_{nullptr};
    bpf_program* prog_{nullptr};
    int stop_event_{-1};
    std::atomic<bool> stop_flag_{false};
    float stats_interval_{0.0f};
    timeval last_ts_{};
    int datalink_{0};
};

#endif
