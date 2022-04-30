#include <fastcap/device.hpp>
#include <fastcap/sysinfo.hpp>

#include <cstring>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <linux/if_packet.h>

static std::string_view iface_name(int id) {
    static thread_local char if_name[IF_NAMESIZE];
    auto name = if_indextoname(id, if_name);
    if (name == nullptr) {
        return std::string_view();
    } else {
        return name;
    }
}

Device::Device(int id) : id_(id) {}

Device::Device(const std::string& name)
    : Device(name.c_str()) {}

Device::Device(const char* name)
    : id_(if_nametoindex(name)) {}

std::string Device::name() const {
    return std::string(iface_name(id_));
}

std::vector<IPv4Subnet> Device::ipv4_addrs() const {
    std::vector<IPv4Subnet> ret;
    struct ifaddrs* addrs;
    if (getifaddrs(&addrs) == 0) {
        auto name = iface_name(id_);
        for (auto addr = addrs; addr != nullptr; addr = addr->ifa_next) {
            if (addr->ifa_addr != nullptr && name == addr->ifa_name) {
                if (addr->ifa_addr->sa_family == AF_INET) {
                    IPv4Subnet val;
                    std::memcpy(val.addr.data(), &((struct sockaddr_in *)addr->ifa_addr)->sin_addr.s_addr, 4);
                    std::memcpy(val.mask.data(), &((struct sockaddr_in *)addr->ifa_netmask)->sin_addr.s_addr, 4);
                    ret.push_back(val);
                }
            }
        }
        freeifaddrs(addrs);
    }
    return ret;
}

static uint8_t prefix_len_from_mask(const IPv6& mask) {
    uint8_t prefix_len = 0;
    for (auto byte : mask) {
        for (auto bit = 0x80; bit != 0; bit >>= 1) {
            if ((byte & bit) == 0) {
                return prefix_len;
            }
            ++prefix_len;
        }
    }
    return prefix_len;
}

std::vector<IPv6Subnet> Device::ipv6_addrs() const {
    std::vector<IPv6Subnet> ret;
    struct ifaddrs* addrs;
    if (getifaddrs(&addrs) == 0) {
        auto name = iface_name(id_);
        for (auto addr = addrs; addr != nullptr; addr = addr->ifa_next) {
            if (addr->ifa_addr != nullptr && name == addr->ifa_name) {
                if (addr->ifa_addr->sa_family == AF_INET6) {
                    IPv6Subnet val;
                    std::memcpy(val.addr.data(), &((struct sockaddr_in6 *)addr->ifa_addr)->sin6_addr.s6_addr, 16);
                    IPv6 mask;
                    std::memcpy(mask.data(), &((struct sockaddr_in6 *)addr->ifa_netmask)->sin6_addr.s6_addr, 16);
                    val.prefix_len = prefix_len_from_mask(mask);
                    ret.push_back(val);
                }
            }
        }
        freeifaddrs(addrs);
    }
    return ret;
}

std::optional<MAC> Device::mac_addr() const {
    struct ifaddrs* addrs;
    if (getifaddrs(&addrs) == 0) {
        auto name = iface_name(id_);
        for (auto addr = addrs; addr != nullptr; addr = addr->ifa_next) {
            if (addr->ifa_addr != nullptr && name == addr->ifa_name) {
                if (addr->ifa_addr->sa_family == AF_PACKET) {
                    MAC ret;
                    std::memcpy(ret.data(), ((struct sockaddr_ll*)addr->ifa_addr)->sll_addr, 6);
                    return ret;
                }
            }
        }
        freeifaddrs(addrs);
    }
    return std::nullopt;
}

uint64_t Device::speed() const {
    return iface_speed(iface_name(id_));
}

std::string Device::hardware() const {
    return iface_hardware(iface_name(id_));
}
