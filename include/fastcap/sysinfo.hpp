#ifndef FASTCAP_SYSINFO_HPP
#define FASTCAP_SYSINFO_HPP

#include <cstdint>
#include <string>
#include <string_view>

std::string cpu_model();

std::string os_version();

std::string iface_hardware(std::string_view iface);

uint64_t iface_speed(std::string_view iface);

#endif
