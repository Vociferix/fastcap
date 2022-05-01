#include <fastcap/sniffer.hpp>
#include <fastcap/writer.hpp>
#include <fastcap/pcapng.hpp>

#include <CLI/CLI.hpp>
#include <spdlog/spdlog.h>
#include <spdlog/async.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>

#include <unistd.h>

#include <atomic>
#include <csignal>
#include <cstdlib>
#include <exception>
#include <thread>

std::atomic<Sniffer*> g_sniffer{nullptr};

static void signal_handler(int) {
    const auto invalid_ptr = reinterpret_cast<Sniffer*>(1);
    auto sniffer = g_sniffer.exchange(invalid_ptr, std::memory_order_relaxed);
    if (sniffer != nullptr && sniffer != invalid_ptr) {
        auto rc = sniffer->stop();
        if (rc != 0) {
            std::exit(rc);
        }
    }
}

void init_signal_handler() {
    struct sigaction handler_info{};
    handler_info.sa_handler = signal_handler;
    if (sigemptyset(&handler_info.sa_mask) != 0) {
        spdlog::error("error setting up signal handler: {}", strerror(errno));
        std::exit(1);
    }
    handler_info.sa_flags = 0;
    if (sigaction(SIGINT, &handler_info, nullptr) != 0) {
        spdlog::error("error setting up signal handler: {}", strerror(errno));
        std::exit(1);
    }
}

static int capture(const Config& config) {
    spdlog::trace("Run thread started");
    Sniffer sniffer{config};
    WriterSet writers{config, sniffer.datalink()};
    if (!sniffer.ok()) {
        writers.join();
        return 1;
    }
    Sniffer* tmp = nullptr;
    if (g_sniffer.compare_exchange_strong(tmp, &sniffer, std::memory_order_relaxed)) {
        auto rc = sniffer.run(writers);
        if (rc != 0) {
            writers.join();
            return rc;
        }
    }
    return writers.join();
}

int fastcap(int argc, const char* const* argv) {
    Config config;
    std::string log_level{"info"};
    std::string log_file;
    std::string pcapng_out;
    std::vector<std::string> pcapng_in;

    CLI::App app("Fastcap");
    app.add_option("-l,--log-level", log_level, "Logging level: trace, debug, info, warning, error, off")->capture_default_str();
    app.add_option("--log-file", log_file, "File to write logs to (stdout if not specified)");

    auto capture_cmd = app.add_subcommand("capture", "Capture traffic from a network interface and dump in the fastcap file format")->fallthrough();
    capture_cmd->add_option("interface", config.iface, "Interface from which to capture network traffic")->required();
    capture_cmd->add_option("output", config.fname, "Output filename")->required();
    capture_cmd->add_option("-c,--file-count", config.num_files, "Number of parallel files to write")->capture_default_str()->check(CLI::Range(1, std::numeric_limits<int>::max()));
    capture_cmd->add_option("-t,--stats-interval", config.stats_interval, "Time between statistics measurements in seconds (defaults to once at the end of capture)")->check(CLI::NonNegativeNumber);
    capture_cmd->add_option("-s,--snaplen", config.snaplen, "Packet snapshot length in bytes")->capture_default_str()->check(CLI::PositiveNumber);
    capture_cmd->add_option("-b,--bufsize", config.bufsz, "Buffer size in MiB for capturing packets")->capture_default_str()->check(CLI::Range(1, std::numeric_limits<int>::max() >> (20 - 1)));
    capture_cmd->add_flag("-n,--nano", config.nano, "Record timestamps with nanosecond precision");
    capture_cmd->add_flag("-p,--promisc", config.promisc, "Enable promiscuous mode on the interface for capture");
    capture_cmd->add_flag("-m,--rfmon", config.rfmon, "Enable monitor mode on the interface for capture");
    capture_cmd->add_flag("-i,--immediate", config.immediate, "Write all packets as they arrive instead of buffering");

    auto build_cmd = app.add_subcommand("build", "Post-process fastcap capture files into a single PCAPNG capture file");
    build_cmd->add_option("pcapng", pcapng_out, "PCAPNG file to write")->required();
    build_cmd->add_option("captures", pcapng_in, "Fastcap capture files to process")->required()->check(CLI::ExistingFile);

    build_cmd->excludes(capture_cmd);
    app.require_subcommand(1);

    CLI11_PARSE(app, argc, argv);

    config.bufsz <<= (20 - 1);

    spdlog::init_thread_pool(8192, 1);
    auto lvl = spdlog::level::info;
    if (log_level == "trace") {
        lvl = spdlog::level::trace;
    } else if (log_level == "debug") {
        lvl = spdlog::level::debug;
    } else if (log_level == "info") {
        lvl = spdlog::level::info;
    } else if (log_level == "warning") {
        lvl = spdlog::level::warn;
    } else if (log_level == "error") {
        lvl = spdlog::level::err;
    } else if (log_level == "off") {
        lvl = spdlog::level::off;
    }
    if (app.count("--log-file") > 0) {
        auto logger = spdlog::create_async<spdlog::sinks::basic_file_sink_mt>("logfile", log_file);
        logger->set_level(lvl);
        spdlog::set_default_logger(std::move(logger));
    } else {
        auto logger = spdlog::create_async<spdlog::sinks::stdout_color_sink_mt>("console");
        logger->set_level(lvl);
        spdlog::set_default_logger(std::move(logger));
    }

    if (app.got_subcommand(capture_cmd)) {
        init_signal_handler();
        int rc = 0;
        std::thread worker{[&config, &rc] { rc = capture(config); }};
        worker.join();
        return rc;
    } else if (app.got_subcommand(build_cmd)) {
        write_pcapng(pcapng_out, pcapng_in);
        return 0;
    }
    spdlog::error("unknown command");
    return 1;
}

int main(int argc, char** argv) {
    try {
        try {
            return fastcap(argc, argv);
        } catch (const std::exception& e) {
            spdlog::error("{}", e.what());
        } catch (...) {
            spdlog::error("unknown error");
        }
    } catch (...) {
    }
    return 1;
}
