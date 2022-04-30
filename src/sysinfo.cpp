#include <fastcap/sysinfo.hpp>

#include <cctype>
#include <filesystem>
#include <fstream>
#include <string_view>

#include <sys/utsname.h>

#include <spdlog/fmt/fmt.h>

static std::string_view trim_front(std::string_view s) noexcept {
    size_t pos = 0;
    while (pos < s.size() && std::isspace(s[pos])) {
        ++pos;
    }
    return s.substr(pos);
}

static std::string_view trim_back(std::string_view s) noexcept {
    size_t pos = s.size();
    while (pos > 0 && std::isspace(s[pos-1])) {
        --pos;
    }
    return s.substr(0, pos);
}

static std::string_view trim(std::string_view s) noexcept {
    return trim_back(trim_front(s));
}

static std::pair<std::string_view, std::string_view>
split(std::string_view s, char c) noexcept {
    auto pos = s.find_first_of(c);
    if (pos == std::string_view::npos) {
        return {s, std::string_view{}};
    } else {
        return {s.substr(0, pos), s.substr(pos + 1)};
    }
}

static std::string unquote(std::string_view s) noexcept {
    if (s.size() < 2 || s.front() != '"' || s.back() != '"') {
        return std::string();
    }
    s = s.substr(1, s.size() - 2);
    std::string ret;
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '\\') {
            if (++i == s.size()) {
                break;
            }
            switch (s[i]) {
                case 'a':
                    ret.push_back('\a');
                    break;
                case 'b':
                    ret.push_back('\b');
                    break;
                case 't':
                    ret.push_back('\t');
                    break;
                case 'v':
                    ret.push_back('\v');
                    break;
                case 'f':
                    ret.push_back('\f');
                    break;
                case 'n':
                    ret.push_back('\n');
                    break;
                case 'r':
                    ret.push_back('\r');
                    break;
                case '\'':
                    ret.push_back('\'');
                    break;
                case '"':
                    ret.push_back('"');
                    break;
                case '\\':
                    ret.push_back('\\');
                    break;
                default:
                    break;
            }
        } else {
            ret.push_back(s[i]);
        }
    }
    return ret;
}

std::string cpu_model() {
    std::ifstream file{"/proc/cpuinfo"};
    std::string line;
    while (std::getline(file, line)) {
        auto entry = split(line, ':');
        auto name = trim(entry.first);
        auto value = trim(entry.second);
        if (name == "model name") {
            return std::string(value);
        }
    }
    return std::string();
}

static std::string etc_os_release() {
    if (!std::filesystem::exists("/etc/os-release")) {
        return std::string();
    }
    std::ifstream file{"/etc/os-release"};
    std::string line;
    std::string name;
    std::string version;
    std::string pretty_name;
    while (std::getline(file, line)) {
        auto entry = split(line, '=');
        auto nam = trim(entry.first);
        if (nam == "NAME") {
            name = unquote(trim(entry.second));
        } else if (nam == "VERSION") {
            version = unquote(trim(entry.second));
        } else if (nam == "PRETTY_NAME") {
            pretty_name = unquote(trim(entry.second));
        }
    }
    if (!pretty_name.empty()) {
        return pretty_name;
    } else if (!name.empty()) {
        if (!version.empty()) {
            return name + ' ' + version;
        } else {
            return name;
        }
    } else {
        return std::string();
    }
}

static std::string etc_issue() {
    if (!std::filesystem::exists("/etc/issue")) {
        return std::string();
    }

    std::ifstream file{"/etc/issue"};
    std::string line;
    if (std::getline(file, line)) {
        std::string ret;
        for (size_t i = 0; i < line.size(); ++i) {
            if (line[i] == '\\') {
                ++i;
            } else {
                ret.push_back(line[i]);
            }
        }
        return std::string(trim(ret));
    } else {
        return std::string();
    }
}

static std::string etc_lsb_release() {
    if (!std::filesystem::exists("/etc/lsb-release")) {
        return std::string();
    }
    std::ifstream file{"/etc/lsb-release"};
    std::string line;
    while (std::getline(file, line)) {
        auto entry = split(line, '=');
        auto name = trim(entry.first);
        if (name == "DISTRIB_DESCRIPTION") {
            return std::string(unquote(trim(entry.second)));
        }
    }
    return std::string();
}

static std::string kernel_version() {
    struct utsname name;
    if (uname(&name) < 0) {
        return std::string();
    }
    return fmt::format("{} {}", name.sysname, name.release);
}

static std::string distrib_version() {
    auto ver = etc_os_release();
    if (ver.empty()) {
        ver = etc_lsb_release();
        if (ver.empty()) {
            ver = etc_issue();
        }
    }
    return ver;
}

std::string os_version() {
    auto distrib = distrib_version();
    auto kernel = kernel_version();
    if (distrib.empty()) {
        if (kernel.empty()) {
            return std::string();
        } else {
            return kernel;
        }
    } else {
        if (kernel.empty()) {
            return distrib;
        } else {
            return fmt::format("{}, {}", distrib, kernel);
        }
    }
}

static unsigned read_id(const std::string& filepath) {
    if (!std::filesystem::exists(filepath)) {
        return 0;
    }
    std::ifstream file(filepath);
    std::string id_str;
    file >> id_str;
    unsigned id = 0;
    for (size_t i = 2; i < id_str.size(); ++i) {
        if (id_str[i] >= '0' && id_str[i] <= '9') {
            id = (id << 4) | static_cast<unsigned>(id_str[i] - '0');
        } else if (id_str[i] >= 'a' && id_str[i] <= 'f') {
            id = (id << 4) | static_cast<unsigned>(id_str[i] - 'a' + 10);
        } else if (id_str[i] >= 'A' && id_str[i] <= 'F') {
            id = (id << 4) | static_cast<unsigned>(id_str[i] - 'A' + 10);
        } else {
            return 0;
        }
    }
    return id;
}

static unsigned read_rev(const std::string& filepath) {
    std::ifstream file{filepath};
    std::string rev;
    file >> rev;
    if (rev.empty()) {
        return 0;
    } else {
        unsigned ret = 0;
        for (size_t i = 2; i < rev.size(); ++i) {
            if (rev[i] >= '0' && rev[i] <= '9') {
                ret = (ret << 4) | static_cast<unsigned>(rev[i] - '0');
            } else if (rev[i] >= 'a' && rev[i] <= 'f') {
                ret = (ret << 4) | static_cast<unsigned>(rev[i] - 'a' + 10);
            } else if (rev[i] >= 'A' && rev[i] <= 'F') {
                ret = (ret << 4) | static_cast<unsigned>(rev[i] - 'A' + 10);
            } else {
                return 0;
            }
        }
        return ret;
    }
}

static unsigned from_hex_str(std::string_view s) {
    unsigned val = 0;
    for (size_t i = 0; i < 4; ++i) {
        if (s[i] >= '0' && s[i] <= '9') {
            val = (val << 4) | static_cast<unsigned>(s[i] - '0');
        } else if (s[i] >= 'a' && s[i] <= 'f') {
            val = (val << 4) | static_cast<unsigned>(s[i] - 'a' + 10);
        } else if (s[i] >= 'A' && s[i] <= 'F') {
            val = (val << 4) | static_cast<unsigned>(s[i] - 'A' + 10);
        } else {
            return 0;
        }
    }
    return val;
}

static std::string get_device_name(const char* pci_ids, unsigned vendor_id, unsigned device_id, unsigned revision) {
    std::string line;
    std::ifstream file(pci_ids);
    while (std::getline(file, line)) {
        if (line.empty() || line.front() == '#' || line.front() == '\t') {
            continue;
        }

        auto vid = from_hex_str(std::string_view(line).substr(0, 4));
        if (vid == vendor_id) {
            auto vendor_name = std::string(trim(std::string_view(line).substr(4)));
            while (std::getline(file, line)) {
                if (line.size() < 2 || line.front() == '#') {
                    continue;
                }
                if (line.front() != '\t') {
                    if (revision == 0) {
                        return fmt::format("{} Device {:04X}", vendor_name, device_id);
                    } else {
                        return fmt::format("{} Device {:04X} (rev {:02X})", vendor_name, device_id, revision);
                    }
                }
                if (line[1] == '\t') {
                    continue;
                }

                auto did = from_hex_str(std::string_view(line).substr(1, 4));
                if (did == device_id) {
                    auto device_name = std::string(trim(std::string_view(line).substr(5)));
                    if (revision == 0) {
                        return fmt::format("{} {}", vendor_name, device_name);
                    } else {
                        return fmt::format("{} {} (rev {:02X})", vendor_name, device_name, revision);
                    }
                }
            }
        }
    }
    if (revision == 0) {
        return fmt::format("Vendor {:04X} Device {:04X}", vendor_id, device_id);
    } else {
        return fmt::format("Vendor {:04X} Device {:04X} (rev {:02X})", vendor_id, device_id, revision);
    }
}

static constexpr const char* pci_ids_paths[] = {
    "/usr/share/pci.ids",
    "/usr/share/misc/pci.ids",
    "/usr/share/hwdata/pci.ids",
    "/var/lib/pciutils/pci.ids"
};

static std::string get_device_name(unsigned vendor_id, unsigned device_id, unsigned revision) {
    for (auto path : pci_ids_paths) {
        if (std::filesystem::exists(path)) {
            auto name = get_device_name(path, vendor_id, device_id, revision);
            if (!name.empty()) {
                return name;
            }
        }
    }
    return std::string();
}

std::string iface_hardware(std::string_view iface) {
    auto device_id_path = fmt::format("/sys/class/net/{}/device/device", iface);
    auto vendor_id_path = fmt::format("/sys/class/net/{}/device/vendor", iface);
    auto revision_path = fmt::format("/sys/class/net/{}/device/revision", iface);

    if (!std::filesystem::exists(vendor_id_path)) {
        return std::string();
    }

    auto device_id = read_id(device_id_path);
    auto vendor_id = read_id(vendor_id_path);
    auto revision = read_rev(revision_path);
    auto name = get_device_name(vendor_id, device_id, revision);
    if (name.empty()) {
        return "Unknown device";
    } else {
        return name;
    }
}

uint64_t iface_speed(std::string_view iface) {
    auto filepath = fmt::format("/sys/class/net/{}/speed", iface);
    if (std::filesystem::exists(filepath)) {
        std::ifstream file{filepath};
        std::string speed;
        file >> speed;
        uint64_t val = 0;
        for (auto c : trim(speed)) {
            if (c >= '0' && c <= '9') {
                val = (val * 10) + static_cast<uint64_t>(c - '0');
            } else {
                return 0;
            }
        }
        return val * 1'000'000;
    } else {
        return 0;
    }
}
