#ifndef FASTCAP_DEVICE_HPP
#define FASTCAP_DEVICE_HPP

#include <array>
#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

using IPv4 = std::array<uint8_t, 4>;
using IPv6 = std::array<uint8_t, 16>;
using MAC = std::array<uint8_t, 6>;

struct IPv4Subnet {
    IPv4 addr;
    IPv4 mask;
};

struct IPv6Subnet {
    IPv6 addr;
    uint8_t prefix_len;
};

class Device {
  private:
    int id_;

  public:
    Device();
    explicit Device(int id);
    explicit Device(const std::string& name);
    explicit Device(const char* name);

    int id() const;
    std::string name() const;

    std::vector<IPv4Subnet> ipv4_addrs() const;
    std::vector<IPv6Subnet> ipv6_addrs() const;
    std::optional<MAC> mac_addr() const;

    uint64_t speed() const;
    std::string hardware() const;
};

#endif
