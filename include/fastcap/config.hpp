#ifndef FASTCAP_CONFIG_HPP
#define FASTCAP_CONFIG_HPP

#include <string>

struct Config {
    std::string iface;
    std::string fname;
    std::string filter;
    int bufsz{256};
    int snaplen{65536};
    int num_files{1};
    float stats_interval{-1.0f};
    bool nano{false};
    bool promisc{false};
    bool rfmon{false};
    bool immediate{false};
};

#endif
