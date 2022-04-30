#include <fastcap/device.hpp>
#include <fastcap/writer.hpp>

#include <spdlog/spdlog.h>
#include <pcap.h>

#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

class ReaderSet;

static std::array<uint8_t, 4> PADDING = {0, 0, 0, 0};

int main(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <pcapng> <capfile>...\n";
        return 1;
    }

    std::vector<std::string_view> paths;
    for (int i = 2; i < argc; ++i) {
        paths.emplace_back(argv[i]);
    }
    ReaderSet readers{paths};
    PcapNGWriter writer{argv[1], readers};
    writer.write_all();

    return 0;
}
