#ifndef FASTCAP_PCAPNG_HPP
#define FASTCAP_PCAPNG_HPP

#include <fastcap/reader.hpp>

#include <fstream>

class PcapNGWriter {
  private:
    std::ofstream file_;
    ReaderSet* readers_;
    uint64_t start_time_{0};
    uint64_t pkt_count_{0};

    void write(const void* buf, std::streamsize len);

    template <typename T>
    void write(const T* buf);

    std::streamoff position();
    void seek(std::streamoff pos);

    std::pair<uint32_t, uint32_t> timestamp(uint64_t sec, uint64_t frac);

    void write_shb();
    void write_idb();
    void write_epb(const PktHdr& hdr, const std::vector<uint8_t>& data);
    void write_isb(const StatHdr& hdr);

  public:
    explicit PcapNGWriter(const std::string& filepath, ReaderSet& readers);

    void write_all();
};

void write_pcapng(const std::string& out_file, ReaderSet& readers);
void write_pcapng(const std::string& out_file, const std::vector<std::string>& in_files);

#endif
