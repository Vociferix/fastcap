find_path(PCAP_ROOT_DIR
    NAMES include/pcap.h
)

find_path(PCAP_INCLUDE_DIR
    NAMES pcap.h
    HINTS "${PCAP_ROOT_DIR}/include"
)

if(WIN32 AND ${CMAKE_SIZEOF_VOID_P} EQUAL 8)
    set(HINT_DIR "${PCAP_ROOT_DIR}/lib/x64/" "${HINT_DIR}")
endif()

find_library(PCAP_LIBRARIES
    NAMES pcap wpcap
    HINTS "${HINT_DIR}"
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(PCAP DEFAULT_MSG
    PCAP_LIBRARIES
    PCAP_INCLUDE_DIR
)

include(CheckCXXSourceCompiles)
set(CMAKE_REQUIRED_LIBRARIES "${PCAP_LIBRARIES}")
check_cxx_source_compiles("int main() { return 0; }" PCAP_LINKS_SOLO)
set(CMAKE_REQUIRED_LIBRARIES)

if(NOT PCAP_LINKS_SOLO)
    find_package(Threads)
    if(THREADS_FOUND)
        set(CMAKE_REQUIRED_LIBRARIES "${PCAP_LIBRARIES}" "${CMAKE_THREAD_LIBS_INIT}")
	check_cxx_source_compiles("int main() { return 0; }" PCAP_NEEDS_THREADS)
	set(CMAKE_REQUIRED_LIBRARIES)
    endif()
    if(THREADS_FOUND AND PCAP_NEEDS_THREADS)
	set(_TMP "${PCAP_LIBRARIES}" "${CMAKE_THREAD_LIBS_INIT}")
	list(REMOVE_DUPLICATES _TMP)
	set(PCAP_LIBRARIES ${_TMP} CACHE STRING "Libraries needed to link against libpcap" FORCE)
    else()
	message(SEND_ERROR "Couldn't determine how to link against libpcap")
    endif()
endif()

include(CheckFunctionExists)
set(CMAKE_REQUIRED_LIBRARIES "${PCAP_LIBRARIES}")
check_function_exists(pcap_get_pfring_id PCAP_PF_RING_AWARE)
set(CMAKE_REQUIRED_LIBRARIES)

mark_as_advanced(
    PCAP_ROOT_DIR
    PCAP_INCLUDE_DIR
    PCAP_LIBRARIES
)
