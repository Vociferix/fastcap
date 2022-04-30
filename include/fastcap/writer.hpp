#ifndef FASTCAP_WRITER_HPP
#define FASTCAP_WRITER_HPP

#include <fastcap/config.hpp>
#include <fastcap/ring_buffer.hpp>

#include <atomic>
#include <thread>
#include <cstdint>
#include <fstream>
#include <vector>

extern "C" {
struct timeval;
struct pcap_pkthdr;
}

class WriterSet;

struct PktHdr {
    uint64_t id;
    uint64_t secs;
    uint64_t frac;
    uint32_t len;
    uint32_t caplen;
};

struct StatHdr {
    uint64_t id;
    uint64_t secs;
    uint64_t frac;
    uint64_t recv;
    uint64_t iface_drops;
    uint64_t os_drops;
};

class Writer {
  private:
    std::thread worker_;
    std::ofstream file_;
    WriterSet* set_;

    void work();

    void launch_worker();

    friend class WriterSet;

  public:
    Writer(WriterSet& set, std::ofstream file);

    void join();
};

class WriterSet {
  private:
    std::vector<Writer> writers_;
    RingBuffer buf_;
    std::atomic<bool> stop_{false};
    uint64_t queue_drops_{0};
    uint64_t entry_count_{0};

    friend class Writer;

  public:
    WriterSet(const Config& config, int datalink);
    WriterSet(const WriterSet&) = delete;
    WriterSet(WriterSet&&) = delete;
    ~WriterSet() = default;
    WriterSet& operator=(const WriterSet&) = delete;
    WriterSet& operator=(WriterSet&&) = delete;

    void write_packet(const pcap_pkthdr& hdr, const uint8_t* bytes);
    void write_stats(const timeval& ts, uint64_t recv, uint64_t iface_drops, uint64_t os_drops);

    int join();
};

#endif
