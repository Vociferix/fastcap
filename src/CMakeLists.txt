set(INCLUDE_DIR "${PROJECT_SOURCE_DIR}/include/fastcap")

add_library(libfastcap STATIC
    "${INCLUDE_DIR}/config.hpp"
    "${INCLUDE_DIR}/device.hpp"
    "${INCLUDE_DIR}/pcapng.hpp"
    "${INCLUDE_DIR}/reader.hpp"
    "${INCLUDE_DIR}/ring_buffer.hpp"
    "${INCLUDE_DIR}/sniffer.hpp"
    "${INCLUDE_DIR}/sysinfo.hpp"
    "${INCLUDE_DIR}/utils.hpp"
    "${INCLUDE_DIR}/writer.hpp"

    device.cpp
    pcapng.cpp
    reader.cpp
    ring_buffer.cpp
    sniffer.cpp
    sysinfo.cpp
    writer.cpp
)

target_compile_features(libfastcap PUBLIC cxx_std_17)

target_include_directories(libfastcap PRIVATE
    ${PCAP_INCLUDE_DIR}
    ${CMAKE_THREAD_LIBS_INIT}
)

target_include_directories(libfastcap PUBLIC
    "${PROJECT_SOURCE_DIR}/include"
)

target_link_libraries(libfastcap PRIVATE
    ${PCAP_LIBRARIES}
)

target_link_libraries(libfastcap PUBLIC
    spdlog::spdlog
)

set_target_properties(libfastcap PROPERTIES OUTPUT_NAME fastcap)

add_executable(fastcap fastcap.cpp)

target_link_libraries(fastcap PRIVATE
    libfastcap
    CLI11::CLI11
    ${CMAKE_THREAD_LIBS_INIT}
)

set_target_properties(fastcap PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}"
)
foreach(CFG ${CMAKE_CONFIGURATION_TYPES})
    string(TOUPPER "${CFG}" CFG)
    set_target_properties(fastcap PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY_${CFG} "${PROJECT_BINARY_DIR}"
    )
endforeach()
